/*
 * adcli
 *
 * Copyright (C) 2012 Red Hat Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA
 *
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"

#include "adcli.h"
#include "adprivate.h"
#include "addisco.h"

#include <gssapi/gssapi_krb5.h>
#include <krb5/krb5.h>
#include <ldap.h>
#include <sasl/sasl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct _adcli_conn_ctx {
	int refs;

	/* Input/output params */
	char *user_name;
	char *user_password;
	char *netbios_computer_name;
	char *full_computer_name;
	char *computer_password;
	char *login_ccache_name;
	int login_ccache_name_is_krb5;
	char *login_keytab_name;
	int login_keytab_name_is_krb5;
	adcli_login_type login_type;
	int logins_allowed;

	char *krb5_conf_dir;
	char *krb5_conf_snippet;

	adcli_password_func password_func;
	adcli_destroy_func password_destroy;
	void *password_data;

	char *host_fqdn;
	char *domain_name;
	char *domain_realm;
	char *domain_controller;
	bool use_ldaps;
	char *canonical_host;
	char *domain_short;
	char *domain_sid;
	adcli_disco *domain_disco;
	enum conn_is_writeable is_writeable;
	char *default_naming_context;
	char *configuration_naming_context;
	char **supported_capabilities;
	char **supported_sasl_mechs;

	/* Connect state */
	LDAP *ldap;
	int ldap_authenticated;
	krb5_context k5;
	krb5_ccache ccache;
	krb5_keytab keytab;
};

static char *try_to_get_fqdn (const char *host_name)
{
	int ret;
	char *fqdn = NULL;
	struct addrinfo *res;
	struct addrinfo hints;

	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_CANONNAME;

	ret = getaddrinfo (host_name, NULL, &hints, &res);
	if (ret != 0) {
		_adcli_err ("Failed to find FQDN: %s", gai_strerror (ret));
		return NULL;
	}

	fqdn = strdup (res->ai_canonname);

	freeaddrinfo (res);

	return fqdn;
}

static adcli_result
ensure_host_fqdn (adcli_result res,
                  adcli_conn *conn)
{
	char hostname[HOST_NAME_MAX + 1];
	char *fqdn = NULL;
	int ret;

	if (res != ADCLI_SUCCESS)
		return res;

	if (conn->host_fqdn) {
		_adcli_info ("Using fully qualified name: %s", conn->host_fqdn);
		return ADCLI_SUCCESS;
	}

	ret = gethostname (hostname, sizeof (hostname));
	if (ret < 0) {
		_adcli_err ("Couldn't get local hostname: %s", strerror (errno));
		return ADCLI_ERR_UNEXPECTED;
	}

	if (strchr (hostname, '.') == NULL) {
		fqdn = try_to_get_fqdn (hostname);
	}
	conn->host_fqdn = fqdn != NULL ? fqdn : strdup (hostname);
	return_unexpected_if_fail (conn->host_fqdn != NULL);
	return ADCLI_SUCCESS;
}

static void
disco_dance_if_necessary (adcli_conn *conn)
{
	if (conn->domain_disco)
		return;

	if (conn->domain_controller)
		adcli_disco_host (conn->domain_controller,
		                  adcli_conn_get_use_ldaps (conn),
		                  &conn->domain_disco);

	else if (conn->domain_name)
		adcli_disco_domain (conn->domain_name,
		                    adcli_conn_get_use_ldaps (conn),
		                    &conn->domain_disco);

	if (conn->domain_disco) {
		if (!conn->domain_short && conn->domain_disco->domain_short) {
			conn->domain_short = strdup (conn->domain_disco->domain_short);
			return_if_fail (conn->domain_short != NULL);
		}
	}
}

static void
no_more_disco (adcli_conn *conn)
{
	if (conn->domain_disco)
		adcli_disco_free (conn->domain_disco);
	conn->domain_disco = NULL;
}

static adcli_result
ensure_domain_and_host (adcli_result res,
                        adcli_conn *conn)
{
	const char *dom;

	if (res != ADCLI_SUCCESS)
		return res;

	if (conn->domain_name) {
		_adcli_info ("Using domain name: %s", conn->domain_name);
		return ADCLI_SUCCESS;
	}

	assert (conn->host_fqdn != NULL);

	disco_dance_if_necessary (conn);

	if (conn->domain_disco && conn->domain_disco->domain) {
		conn->domain_name = strdup (conn->domain_disco->domain);
		return_unexpected_if_fail (conn->domain_name != NULL);

		_adcli_info ("Discovered domain name: %s", conn->domain_name);
		return ADCLI_SUCCESS;
	}

	/* Use the FQDN minus the last part */
	dom = strchr (conn->host_fqdn, '.');

	/* If no dot, or dot is first or last, then fail */
	if (dom == NULL || dom == conn->host_fqdn || dom[1] == '\0') {
		_adcli_err ("Couldn't determine the domain name from host name: %s",
		            conn->host_fqdn);
		return ADCLI_ERR_FAIL;
	}

	conn->domain_name = strdup (dom + 1);
	return_unexpected_if_fail (conn->domain_name != NULL);

	_adcli_info ("Calculated domain name from host fqdn: %s",
	             conn->domain_name);

	return ADCLI_SUCCESS;
}

void
_adcli_calc_netbios_name (const char *host_fqdn,
			  char **netbios_computer_name,
			  char **full_computer_name)
{
	const char *dom;
	char *computer_name = NULL;
	char *truncated_name = NULL;

	/* Use the FQDN minus the last part */
	dom = strchr (host_fqdn, '.');

	/* If dot is first then fail */
	if (dom == host_fqdn) {
		_adcli_err ("Couldn't determine the computer account name from host name: %s",
		            host_fqdn);
		return;

	} else if (dom == NULL) {
		computer_name = strdup (host_fqdn);
		return_if_fail (computer_name != NULL);

	} else {
		computer_name = strndup (host_fqdn, dom - host_fqdn);
		return_if_fail (computer_name != NULL);
	}
	*full_computer_name = computer_name;

	truncated_name = strdup (computer_name);
	return_if_fail (truncated_name != NULL);

	_adcli_str_up (truncated_name);
	if (strlen (truncated_name) > 15) {
		truncated_name[15] = 0;
		_adcli_info ("Truncated computer account name from fqdn: %s", truncated_name);
	} else {
		_adcli_info ("Calculated computer account name from fqdn: %s", truncated_name);
	}
	*netbios_computer_name = truncated_name;

	return;
}

static adcli_result
ensure_computer_name (adcli_result res,
                      adcli_conn *conn)
{

	if (res != ADCLI_SUCCESS)
		return res;

	if (conn->netbios_computer_name && conn->full_computer_name) {
		_adcli_info ("Using computer account name: %s", conn->netbios_computer_name);
		return ADCLI_SUCCESS;
	}

	assert (conn->host_fqdn != NULL);

	_adcli_calc_netbios_name (conn->host_fqdn, &conn->netbios_computer_name, &conn->full_computer_name);
	if (conn->netbios_computer_name == NULL || conn->full_computer_name == NULL)
		return ADCLI_ERR_CONFIG;

	return ADCLI_SUCCESS;
}


static adcli_result
ensure_domain_realm (adcli_result res,
                     adcli_conn *conn)
{
	if (res != ADCLI_SUCCESS)
		return res;

	if (conn->domain_realm) {
		_adcli_info ("Using domain realm: %s", conn->domain_name);
		return ADCLI_SUCCESS;
	}

	conn->domain_realm = strdup (conn->domain_name);
	return_unexpected_if_fail (conn->domain_realm != NULL);

	_adcli_str_up (conn->domain_realm);
	_adcli_info ("Calculated domain realm from name: %s",
	             conn->domain_realm);
	return ADCLI_SUCCESS;
}

static adcli_result
ensure_user_password (adcli_conn *conn)
{
	if (conn->login_ccache_name != NULL ||
	    conn->user_password != NULL)
		return ADCLI_SUCCESS;

	if (conn->password_func) {
		conn->user_password = (conn->password_func) (ADCLI_LOGIN_USER_ACCOUNT,
		                                             conn->user_name, 0,
		                                             conn->password_data);
	}

	if (conn->user_password == NULL) {
		_adcli_err ("No admin password or credential cache specified");
		return ADCLI_ERR_CREDENTIALS;
	}

	return ADCLI_SUCCESS;
}

char *
_adcli_calc_reset_password (const char *computer_name)
{
	char *password;

	assert (computer_name != NULL);
	password = strdup (computer_name);
	return_val_if_fail (password != NULL, NULL);
	_adcli_str_down (password);

	return password;
}

static adcli_result
handle_kinit_krb5_code (adcli_conn *conn,
                        adcli_login_type type,
                        const char *name,
                        krb5_error_code code)
{
	if (code == 0) {
		return ADCLI_SUCCESS;

	} else if (code == ENOMEM) {
		return_unexpected_if_reached ();

	} else if (code == KRB5KDC_ERR_PREAUTH_FAILED ||
	           code == KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN ||
	           code == KRB5KDC_ERR_KEY_EXP ||
	           code == KRB5KDC_ERR_CLIENT_REVOKED ||
	           code == KRB5KDC_ERR_POLICY ||
	           code == KRB5KDC_ERR_ETYPE_NOSUPP ||
	           code == KRB5_PREAUTH_FAILED) {
		if (type == ADCLI_LOGIN_COMPUTER_ACCOUNT) {
			_adcli_err ("Couldn't authenticate as machine account: %s: %s",
			            name, krb5_get_error_message (conn->k5, code));
		} else {
			_adcli_err ("Couldn't authenticate as: %s: %s",
			            name, krb5_get_error_message (conn->k5, code));
		}
		return ADCLI_ERR_CREDENTIALS;

	} else {
		if (type == ADCLI_LOGIN_COMPUTER_ACCOUNT) {
			_adcli_err ("Couldn't get kerberos ticket for machine account: %s: %s",
			            name, krb5_get_error_message (conn->k5, code));
		} else {
			_adcli_err ("Couldn't get kerberos ticket for: %s: %s",
			            name, krb5_get_error_message (conn->k5, code));
		}
		return ADCLI_ERR_DIRECTORY;
	}
}

static void
clear_krb5_conf_snippet (adcli_conn *conn)
{
	if (conn->krb5_conf_snippet) {
		if (unlink (conn->krb5_conf_snippet) < 0) {
			_adcli_warn ("Couldn't remove krb5.conf snippet file: %s: %s",
			             conn->krb5_conf_snippet, strerror (errno));
		}
		free (conn->krb5_conf_snippet);
		conn->krb5_conf_snippet = NULL;
	}
}

static adcli_result
setup_krb5_conf_snippet (adcli_conn *conn)
{
	char *filename;
	char *snippet;
	char *controller;
	int errn;
	int ret;
	int fd;
	mode_t old_mask;

	if (!conn->krb5_conf_dir)
		return ADCLI_SUCCESS;

	/* Already written out the conf snippet */
	if (conn->krb5_conf_snippet)
		return ADCLI_SUCCESS;

	clear_krb5_conf_snippet (conn);

	if (asprintf (&filename, "%s/adcli-krb5-conf-XXXXXX", conn->krb5_conf_dir) < 0)
		return_unexpected_if_reached ();

	if (strchr (conn->domain_controller, ':')) {
		if (asprintf (&controller, "[%s]", conn->domain_controller) < 0)
			controller = NULL;
	} else {
		controller = strdup (conn->domain_controller);
	}

	return_unexpected_if_fail (controller != NULL);

	if (asprintf (&snippet, "[realms]\n"
	                        "  %s = {\n"
	                        "    kdc = %s:88\n"
	                        "    master_kdc = %s:88\n"
	                        "    kpasswd_server = %s\n"
	                        "  }\n"
	                        "[domain_realm]\n"
	                        "  %s = %s\n"
	                        "  %s = %s\n",
	              conn->domain_realm, controller, controller, controller,
	              conn->canonical_host, conn->domain_realm,
	              conn->domain_controller, conn->domain_realm) < 0)
		return_unexpected_if_reached ();

	old_mask = umask (0177);
	fd = mkstemp (filename);
	umask (old_mask);
	if (fd < 0) {
		_adcli_warn ("Couldn't create krb5.conf snippet file in: %s: %s",
		             conn->krb5_conf_dir, strerror (errno));

	} else {
		conn->krb5_conf_snippet = filename;
		ret = _adcli_write_all (fd, snippet, -1);
		errn = errno;

		if (ret >= 0) {
			ret = close (fd);
			errn = errno;

		} else {
			close (fd);
		}

		if (ret < 0) {
			_adcli_warn ("Couldn't write krb5.conf snippet file in: %s: %s",
			             filename, strerror (errn));
			clear_krb5_conf_snippet (conn);
		} else {
			_adcli_info ("Wrote out krb5.conf snippet to %s", filename);
		}
	}

	free (controller);
	free (snippet);

	/* This shouldn't stop joining */
	return ADCLI_SUCCESS;
}

/*
 * HACK: This is to work around a bug in krb5 where if an empty password
 * preauth will fail unless a prompter is present.
 */
static krb5_error_code
null_prompter (krb5_context context,
               void *data,
               const char *name,
               const char *banner,
               int num_prompts,
               krb5_prompt prompts[])
{
	int i;

	for (i = 0; i < num_prompts; i++)
		prompts[i].reply->length = 0;

	return 0;
}

krb5_error_code
_adcli_kinit_computer_creds (adcli_conn *conn,
                             const char *in_tkt_service,
                             krb5_ccache ccache,
                             krb5_creds *creds)
{
	krb5_get_init_creds_opt *opt;
	krb5_principal principal;
	krb5_error_code code;
	krb5_context k5;
	krb5_creds dummy;
	char *new_password;
	const char *password;
	char *sam;

	assert (conn != NULL);

	k5 = adcli_conn_get_krb5_context (conn);

	if (asprintf (&sam, "%s$", conn->netbios_computer_name) < 0)
		return_unexpected_if_reached();

	code = _adcli_krb5_build_principal (k5, sam, conn->domain_realm, &principal);
	return_val_if_fail (code == 0, code);

	code = krb5_get_init_creds_opt_alloc (k5, &opt);
	return_val_if_fail (code == 0, code);

	if (ccache) {
		code = krb5_get_init_creds_opt_set_out_ccache (k5, opt, ccache);
		return_val_if_fail (code == 0, code);
	}

	memset (&dummy, 0, sizeof (dummy));
	if (!creds)
		creds = &dummy;

	password = conn->computer_password;
	new_password = NULL;

	/*
	 * Note that we only prompt for computer account passwords if
	 * explicitly requested.
	 */

	if (conn->keytab) {
		code = krb5_get_init_creds_keytab (k5, creds, principal, conn->keytab,
		                                   0, (char *)in_tkt_service, opt);

	} else {
		if (!password && conn->password_func &&
		    conn->logins_allowed == ADCLI_LOGIN_COMPUTER_ACCOUNT) {
			new_password = (conn->password_func) (ADCLI_LOGIN_COMPUTER_ACCOUNT,
			                                      sam, 0, conn->password_data);
			password = new_password;
		}

		if (password == NULL) {
			new_password = _adcli_calc_reset_password (conn->netbios_computer_name);
			password = new_password;
		}

		code = krb5_get_init_creds_password (k5, creds, principal, (char *)password,
		                                     null_prompter, NULL, 0, (char *)in_tkt_service, opt);

		if (code == 0 && new_password) {
			_adcli_password_free (conn->computer_password);
			conn->computer_password = new_password;
		}
	}

	krb5_free_principal (k5, principal);
	krb5_get_init_creds_opt_free (k5, opt);
	krb5_free_cred_contents (k5, &dummy);

	free (sam);
	return code;
}

krb5_error_code
_adcli_kinit_user_creds (adcli_conn *conn,
                         const char *in_tkt_service,
                         krb5_ccache ccache,
                         krb5_creds *creds)
{
	krb5_get_init_creds_opt *opt;
	krb5_principal principal;
	krb5_error_code code;
	krb5_context k5;
	krb5_creds dummy;

	assert (conn != NULL);

	k5 = adcli_conn_get_krb5_context (conn);

	code = krb5_parse_name (k5, conn->user_name, &principal);
	return_val_if_fail (code == 0, code);

	code = krb5_get_init_creds_opt_alloc (k5, &opt);
	return_val_if_fail (code == 0, code);

	if (ccache) {
		code = krb5_get_init_creds_opt_set_out_ccache (k5, opt, ccache);
		return_val_if_fail (code == 0, code);
	}

	memset (&dummy, 0, sizeof (dummy));
	if (!creds)
		creds = &dummy;

	code = krb5_get_init_creds_password (k5, creds, principal,
	                                     conn->user_password, null_prompter, NULL,
	                                     0, (char *)in_tkt_service, opt);

	krb5_free_principal (k5, principal);
	krb5_get_init_creds_opt_free (k5, opt);
	krb5_free_cred_contents (k5, &dummy);

	return code;
}

static adcli_result
kinit_with_computer_credentials (adcli_conn *conn,
                                 krb5_ccache ccache)
{
	adcli_result res;
	krb5_error_code code;
	int use_default;

	use_default = (conn->computer_password == NULL);

	code = _adcli_kinit_computer_creds (conn, NULL, ccache, NULL);

	if (code == 0) {
		_adcli_info ("Authenticated as %scomputer account: %s",
		             use_default ? "default/reset " : "", conn->netbios_computer_name);

		conn->login_type = ADCLI_LOGIN_COMPUTER_ACCOUNT;
		res = ADCLI_SUCCESS;

	} else {
		res = handle_kinit_krb5_code (conn, ADCLI_LOGIN_COMPUTER_ACCOUNT,
		                              conn->netbios_computer_name, code);
	}

	return res;
}

static adcli_result
kinit_with_user_credentials (adcli_conn *conn,
                             krb5_ccache ccache)
{
	adcli_result res;
	krb5_error_code code;
	char *name;

	/* Build out the admin principal name */
	if (!conn->user_name) {
		if (asprintf (&conn->user_name, "Administrator@%s", conn->domain_realm) < 0)
			return_unexpected_if_reached ();
	} else if (strchr (conn->user_name, '@') == NULL) {
		if (asprintf (&name, "%s@%s", conn->user_name, conn->domain_realm) < 0)
			return_unexpected_if_reached ();
		free (conn->user_name);
		conn->user_name = name;
	}

	res = ensure_user_password (conn);
	if (res != ADCLI_SUCCESS)
		return res;

	code = _adcli_kinit_user_creds (conn, NULL, ccache, NULL);

	if (code == 0) {
		conn->login_type = ADCLI_LOGIN_USER_ACCOUNT;
		_adcli_info ("Authenticated as user: %s", conn->user_name);
		return ADCLI_SUCCESS;
	}

	return handle_kinit_krb5_code (conn, ADCLI_LOGIN_USER_ACCOUNT, conn->user_name, code);
}

static adcli_result
prep_kerberos_and_kinit (adcli_conn *conn)
{
	krb5_error_code code;
	int logged_in = 0;
	krb5_ccache ccache;
	adcli_result res;

	if (conn->login_ccache_name != NULL) {
		if (!conn->ccache) {

			/*
			 * If we already have a kerberos ccache file, just open it. This
			 * serves two purposes:
			 * a) We want to make sure it's present, so we can provide more
			 *    intelligible messages than ldap_sasl_interactive_bind_s()
			 * b) We want to have the ccache member populated so we can use
			 *    it in other operations such as changing the computer password.
			 */

			if (strcmp (conn->login_ccache_name, "") == 0) {
				code = krb5_cc_default (conn->k5, &conn->ccache);
				if (code == 0) {
					free (conn->login_ccache_name);
					conn->login_ccache_name = NULL;
					code = krb5_cc_get_full_name (conn->k5, conn->ccache,
					                              &conn->login_ccache_name);
					conn->login_ccache_name_is_krb5 = 1;
					return_unexpected_if_fail (code == 0);
				}
			} else {
				code = krb5_cc_resolve (conn->k5, conn->login_ccache_name, &conn->ccache);
			}

			if (code != 0) {
				_adcli_err ("Couldn't open kerberos credential cache: %s: %s",
				            conn->login_ccache_name, krb5_get_error_message (NULL, code));
				return ADCLI_ERR_CONFIG;
			}
		}
		return ADCLI_SUCCESS;
	}

	if (conn->login_keytab_name != NULL) {
		if (!conn->keytab) {
			res = _adcli_krb5_open_keytab (conn->k5, conn->login_keytab_name, &conn->keytab);
			if (res != ADCLI_SUCCESS) {
				if (res == ADCLI_ERR_FAIL)
					res = ADCLI_ERR_CONFIG;
				return res;
			}

			if (strcmp (conn->login_keytab_name, "") == 0) {
				free (conn->login_keytab_name);
				conn->login_keytab_name = malloc (MAX_KEYTAB_NAME_LEN);
				code = krb5_kt_get_name (conn->k5, conn->keytab,
				                         conn->login_keytab_name, MAX_KEYTAB_NAME_LEN);
				conn->login_keytab_name_is_krb5 = 1;
				return_unexpected_if_fail (code == 0);
			}
		}
	}

	/* Initialize the credential cache */
	code = krb5_cc_new_unique (conn->k5, "MEMORY", NULL, &ccache);
	return_unexpected_if_fail (code == 0);

	/*
	 * Should we try to connect with computer account default password?
	 * This is the password set by 'Reset Accuont' on a computer object.
	 * If the caller explicitly specified a login name or password, then
	 * go straight to that.
	 */

	if (conn->logins_allowed & ADCLI_LOGIN_COMPUTER_ACCOUNT) {
		res = kinit_with_computer_credentials (conn, ccache);
		logged_in = (res == ADCLI_SUCCESS);
	}

	/* Use login credentials */
	if (!logged_in && (conn->logins_allowed & ADCLI_LOGIN_USER_ACCOUNT)) {
		res = kinit_with_user_credentials (conn, ccache);
		logged_in = (res == ADCLI_SUCCESS);
	}

	if (logged_in) {
		code = krb5_cc_get_full_name (conn->k5, ccache,
		                              &conn->login_ccache_name);
		return_unexpected_if_fail (code == 0);

		conn->ccache = ccache;
		conn->login_ccache_name_is_krb5 = 1;
		ccache = NULL;
		res = ADCLI_SUCCESS;
	} else {
		res = ADCLI_ERR_FAIL;
	}

	if (ccache != NULL)
		krb5_cc_close (conn->k5, ccache);
	return res;

}

/* Not included in ldap.h but documented */
int ldap_init_fd (ber_socket_t fd, int proto, LDAP_CONST char *url, struct ldap **ldp);

static LDAP *
connect_to_address (const char *host,
                    const char *canonical_host,
                    bool use_ldaps)
{
	struct addrinfo *res = NULL;
	struct addrinfo *ai;
	struct addrinfo hints;
	LDAP *ldap = NULL;
	int error = 0;
	char *url;
	int sock;
	int rc;
	int opt_rc;
	const char *port = "389";
	const char *proto = "ldap";
	const char *errmsg = NULL;

	if (use_ldaps) {
		port = "636";
		proto = "ldaps";
		_adcli_info ("Using LDAPS to connect to %s", host);
	}

	memset (&hints, '\0', sizeof(hints));
#ifdef AI_ADDRCONFIG
	hints.ai_flags |= AI_ADDRCONFIG;
#endif
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	if (!canonical_host)
		canonical_host = host;

	rc = getaddrinfo (host, port, &hints, &res);
	if (rc != 0) {
		_adcli_err ("Couldn't resolve host name: %s: %s", host, gai_strerror (rc));
		return NULL;
	}

	for (ai = res; ai != NULL; ai = ai->ai_next) {
		/* coverity[overwrite_var] */
		sock = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock < 0) {
			error = errno;
		} else if (connect (sock, ai->ai_addr, ai->ai_addrlen) < 0) {
			error = errno;
			close (sock);
		} else {
			error = 0;
			if (asprintf (&url, "%s://%s", proto, canonical_host) < 0)
				return_val_if_reached (NULL);
			rc = ldap_init_fd (sock, 1, url, &ldap);
			free (url);

			if (rc != LDAP_SUCCESS) {
				_adcli_err ("Couldn't initialize LDAP connection: %s:",
				            ldap_err2string (rc));
				break;
			}

			if (use_ldaps) {
				rc = ldap_install_tls (ldap);
				if (rc != LDAP_SUCCESS) {
					opt_rc = ldap_get_option (ldap,
					                          LDAP_OPT_DIAGNOSTIC_MESSAGE,
					                          (void *) &errmsg);
					if (opt_rc != LDAP_SUCCESS) {
						errmsg = NULL;
					}
					_adcli_err ("Couldn't initialize TLS [%s]: %s",
					            ldap_err2string (rc),
					            errmsg == NULL ? "- no details -"
					                           : errmsg);
					ldap_unbind_ext_s (ldap, NULL, NULL);
					ldap = NULL;
					break;
				}
			}
		}
	}

	if (!ldap && error)
		_adcli_err ("Couldn't connect to host: %s: %s", host, strerror (error));

	freeaddrinfo (res);
	/* coverity[leaked_handle] - the socket is carried inside the ldap struct */
	return ldap;
}

static adcli_result
connect_and_lookup_naming (adcli_conn *conn,
                           adcli_disco *disco)
{
	char *canonical_host;
	LDAPMessage *results;
	adcli_result res;
	LDAP *ldap;
	int ret;
	int ver;

	char *attrs[] = {
		"defaultNamingContext",
		"configurationNamingContext",
		"supportedCapabilities",
		"supportedSASLMechanisms",
		NULL
	};

	assert (conn->ldap == NULL);

	canonical_host = disco->host_name;
	if (!canonical_host)
		canonical_host = disco->host_addr;

	ldap = connect_to_address (disco->host_addr, canonical_host,
	                           adcli_conn_get_use_ldaps (conn));
	if (ldap == NULL)
		return ADCLI_ERR_DIRECTORY;

	ver = LDAP_VERSION3;
	if (ldap_set_option (ldap, LDAP_OPT_PROTOCOL_VERSION, &ver) != 0)
		return_unexpected_if_reached ();

	if (ldap_set_option (ldap, LDAP_OPT_REFERRALS, LDAP_OPT_OFF) != 0)
		return_unexpected_if_reached ();

	/* Don't force GSSAPI to use reverse DNS */
	if (ldap_set_option (ldap, LDAP_OPT_X_SASL_NOCANON, LDAP_OPT_ON) != 0)
		return_unexpected_if_reached ();

	/*
	 * We perform this lookup whether or not we want to lookup the
	 * naming context, as it also connects to the LDAP server.
	 */
	ret = ldap_search_ext_s (ldap, "", LDAP_SCOPE_BASE, "(objectClass=*)",
	                         attrs, 0, NULL, NULL, NULL, -1, &results);
	if (ret != LDAP_SUCCESS) {
		res = _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                  "Couldn't connect to LDAP server: %s", disco->host_addr);
		ldap_unbind_ext_s (ldap, NULL, NULL);
		return res;
	}

	if (conn->default_naming_context == NULL) {
		conn->default_naming_context = _adcli_ldap_parse_value (ldap, results,
		                                                        "defaultNamingContext");
	}

	if (conn->configuration_naming_context == NULL) {
		conn->configuration_naming_context = _adcli_ldap_parse_value (ldap, results,
		                                                              "configurationNamingContext");
	}

	if (conn->supported_capabilities == NULL) {
		conn->supported_capabilities = _adcli_ldap_parse_values (ldap, results,
		                                                         "supportedCapabilities");
	}

	if (conn->supported_sasl_mechs == NULL) {
		conn->supported_sasl_mechs = _adcli_ldap_parse_values (ldap, results,
		                                                       "supportedSASLMechanisms");
	}

	ldap_msgfree (results);

	if (conn->default_naming_context == NULL) {
		_adcli_err ("No valid LDAP naming context on domain controller: %s", disco->host_addr);
		ldap_unbind_ext_s (ldap, NULL, NULL);
		return ADCLI_ERR_DIRECTORY;
	}

	if (conn->configuration_naming_context == NULL) {
		if (asprintf (&conn->configuration_naming_context,
		              "CN=Configuration,%s", conn->default_naming_context))
			return_unexpected_if_reached ();
	}

	conn->ldap = ldap;

	free (conn->canonical_host);
	conn->canonical_host = strdup (canonical_host);
	return_unexpected_if_fail (conn->canonical_host != NULL);

	adcli_conn_set_domain_controller (conn, disco->host_addr);

	return ADCLI_SUCCESS;
}

static int
sasl_interact (LDAP *ld,
               unsigned flags,
               void *defaults,
               void *interact)
{
	sasl_interact_t *in = (sasl_interact_t *)interact;
	return_val_if_fail (ld != NULL, LDAP_PARAM_ERROR);

	while (in->id != SASL_CB_LIST_END) {
		switch (in->id) {
		case SASL_CB_GETREALM:
		case SASL_CB_USER:
		case SASL_CB_PASS:
			if (in->defresult)
				in->result = in->defresult;
			else
				in->result = "";
			in->len = strlen (in->result);
			break;
		case SASL_CB_AUTHNAME:
			if (in->defresult)
				in->result = in->defresult;
			else
				in->result = "";
			in->len = strlen (in->result);
			break;
		case SASL_CB_NOECHOPROMPT:
		case SASL_CB_ECHOPROMPT:
			return LDAP_UNAVAILABLE;
		}
		in++;
	}

	return LDAP_SUCCESS;
}

static adcli_disco *
desperate_for_disco (adcli_conn *conn)
{
	adcli_disco *disco;

	if (!conn->domain_name || !conn->domain_controller)
		return NULL;

	disco = calloc (1, sizeof (adcli_disco));
	return_val_if_fail (disco != NULL, NULL);

	disco->domain = strdup (conn->domain_name);
	return_val_if_fail (disco->domain != NULL, NULL);

	disco->host_addr = strdup (conn->domain_controller);
	return_val_if_fail (disco->host_addr, NULL);

	disco->host_name = strdup (conn->domain_controller);
	return_val_if_fail (disco->host_name, NULL);

	assert (adcli_disco_usable (disco) != ADCLI_DISCO_UNUSABLE);
	return disco;
}

static adcli_result
connect_to_directory (adcli_conn *conn)
{
	adcli_result res = ADCLI_ERR_UNEXPECTED;
	adcli_disco *disco;
	int had_any = 0;

	if (conn->ldap)
		return ADCLI_SUCCESS;

	disco_dance_if_necessary (conn);

	if (!conn->domain_disco)
		conn->domain_disco = desperate_for_disco (conn);

	for (disco = conn->domain_disco; disco != NULL; disco = disco->next) {
		if (!adcli_disco_usable (disco))
			continue;
		res = connect_and_lookup_naming (conn, disco);
		if (res == ADCLI_SUCCESS || res == ADCLI_ERR_UNEXPECTED)
			return res;
		had_any = 1;
	}

	if (!had_any) {
		_adcli_err ("Couldn't find usable domain controller to connect to");
		return ADCLI_ERR_CONFIG;
	}

	return res;
}

static adcli_result
authenticate_to_directory (adcli_conn *conn)
{
	OM_uint32 status;
	OM_uint32 minor;
	ber_len_t ssf;
	int ret;
	const char *mech = "GSSAPI";

	if (conn->ldap_authenticated)
		return ADCLI_SUCCESS;

	assert (conn->ldap);
	assert (conn->login_ccache_name != NULL);

	/* Sets the credential cache GSSAPI to use (for this thread) */
	status = gss_krb5_ccache_name (&minor, conn->login_ccache_name, NULL);
	return_unexpected_if_fail (status == 0);

	if (adcli_conn_get_use_ldaps (conn)) {
		/* do not use SASL encryption on LDAPS connection */
		ssf = 0;
		ret = ldap_set_option (conn->ldap, LDAP_OPT_X_SASL_SSF_MIN, &ssf);
		return_unexpected_if_fail (ret == 0);
		ret = ldap_set_option (conn->ldap, LDAP_OPT_X_SASL_SSF_MAX, &ssf);
		return_unexpected_if_fail (ret == 0);
	} else {
		/* Clumsily tell ldap + cyrus-sasl that we want encryption */
		ssf = 1;
		ret = ldap_set_option (conn->ldap, LDAP_OPT_X_SASL_SSF_MIN, &ssf);
		return_unexpected_if_fail (ret == 0);
	}

	/* There are issues with cryrus-sasl and GSS-SPNEGO with TLS even if
	 * ssf_max is set to 0. To be on the safe side GSS-SPNEGO is only used
	 * without LDAPS. */
	if (adcli_conn_server_has_sasl_mech (conn, "GSS-SPNEGO")
	                     && !adcli_conn_get_use_ldaps (conn)) {
		mech =  "GSS-SPNEGO";
	}
	_adcli_info ("Using %s for SASL bind", mech);

	ret = ldap_sasl_interactive_bind_s (conn->ldap, NULL, mech, NULL, NULL,
	                                    LDAP_SASL_QUIET, sasl_interact, NULL);

	/* Clear the credential cache GSSAPI to use (for this thread) */
	status = gss_krb5_ccache_name (&minor, NULL, NULL);
	return_unexpected_if_fail (status == 0);

	if (ret != 0) {
		return _adcli_ldap_handle_failure (conn->ldap, ADCLI_ERR_CREDENTIALS,
		                                   "Couldn't authenticate to active directory");
	}

	conn->ldap_authenticated = 1;
	return ADCLI_SUCCESS;
}

static void
lookup_short_name (adcli_conn *conn)
{
	char *attrs[] = { "nETBIOSName", NULL, };
	LDAPMessage *results;
	char *partition_dn;
	char *value;
	char *filter;
	int ret;

	free (conn->domain_short);
	conn->domain_short = NULL;

	if (asprintf (&partition_dn, "CN=Partitions,%s", conn->configuration_naming_context) < 0)
		return_if_reached ();

	value = _adcli_ldap_escape_filter (conn->default_naming_context);
	return_if_fail (value != NULL);

	if (asprintf (&filter, "(&(nCName=%s)(nETBIOSName=*))", value) < 0)
		return_if_reached ();

	ret = ldap_search_ext_s (conn->ldap, partition_dn, LDAP_SCOPE_ONELEVEL,
	                         filter, attrs, 0, NULL, NULL, NULL, -1, &results);

	free (partition_dn);
	free (filter);
	free (value);

	if (ret == LDAP_SUCCESS) {
		conn->domain_short = _adcli_ldap_parse_value (conn->ldap, results, "nETBIOSName");
		ldap_msgfree (results);

		if (conn->domain_short)
			_adcli_info ("Looked up short domain name: %s", conn->domain_short);
		else
			_adcli_err ("No short domain name found");
	} else {
		_adcli_ldap_handle_failure (conn->ldap, ADCLI_ERR_DIRECTORY,
		                            "Couldn't lookup domain short name");
	}
}

static void
lookup_domain_sid (adcli_conn *conn)
{
	char *attrs[] = { "objectSid", NULL, };
	LDAPMessage *results;
	int ret;

	free (conn->domain_sid);
	conn->domain_sid = NULL;

	ret = ldap_search_ext_s (conn->ldap, conn->default_naming_context, LDAP_SCOPE_BASE,
	                         NULL, attrs, 0, NULL, NULL, NULL, -1, &results);
	if (ret == LDAP_SUCCESS) {
		conn->domain_sid = _adcli_ldap_parse_sid (conn->ldap, results, "objectSid");
		ldap_msgfree (results);

		if (conn->domain_sid)
			_adcli_info ("Looked up domain SID: %s", conn->domain_sid);
		else
			_adcli_err ("No domain SID found");
	} else {
		_adcli_ldap_handle_failure (conn->ldap, ADCLI_ERR_DIRECTORY,
		                            "Couldn't lookup domain SID");
	}
}

static void
lookup_is_writeable (adcli_conn *conn)
{
	char *attrs[] = { "NetLogon", NULL };
	LDAPMessage *results;
	int ret;

	ret = ldap_search_ext_s (conn->ldap, "", LDAP_SCOPE_BASE,
	                         "(&(NtVer=\\06\\00\\00\\00)(AAC=\\00\\00\\00\\00))",
	                         attrs, 0, NULL, NULL, NULL, -1, &results);
	if (ret == LDAP_SUCCESS) {
		conn->is_writeable = disco_get_writeable (conn->ldap, results);
		ldap_msgfree (results);
	} else {
		_adcli_ldap_handle_failure (conn->ldap, ADCLI_ERR_DIRECTORY,
		                            "Couldn't lookup writeable state");
		conn->is_writeable = IS_UNKNOWN;
	}
}

static void
conn_clear_state (adcli_conn *conn)
{
	conn->ldap_authenticated = 0;

	if (conn->ldap)
		ldap_unbind_ext_s (conn->ldap, NULL, NULL);
	conn->ldap = NULL;

	free (conn->canonical_host);
	conn->canonical_host = NULL;

	if (conn->ccache)
		krb5_cc_close (conn->k5, conn->ccache);
	conn->ccache = NULL;

	if (conn->keytab)
		krb5_kt_close (conn->k5, conn->keytab);
	conn->keytab = NULL;

	if (conn->k5)
		krb5_free_context (conn->k5);
	conn->k5 = NULL;
}

adcli_result
adcli_conn_discover (adcli_conn *conn)
{
	adcli_result res = ADCLI_SUCCESS;

	return_unexpected_if_fail (conn != NULL);

	adcli_clear_last_error ();

	/* Basic discovery and figuring out conn params */
	res = ensure_host_fqdn (res, conn);
	res = ensure_domain_and_host (res, conn);
	res = ensure_computer_name (res, conn);
	res = ensure_domain_realm (res, conn);

	return res;
}

adcli_result
adcli_conn_connect (adcli_conn *conn)
{
	adcli_result res = ADCLI_SUCCESS;

	return_unexpected_if_fail (conn != NULL);

	res = adcli_conn_discover (conn);
	if (res != ADCLI_SUCCESS)
		return res;

	/* - Connect to LDAP server */
	res = connect_to_directory (conn);
	if (res != ADCLI_SUCCESS)
		return res;

	/* Guarantee consistency and communication with one dc */
	res = setup_krb5_conf_snippet (conn);
	if (res != ADCLI_SUCCESS)
		return res;

	return_unexpected_if_fail (conn->k5 == NULL);
	res = _adcli_krb5_init_context (&conn->k5);
	if (res != ADCLI_SUCCESS)
		return res;

	/* Login with admin credentials now, setup login ccache */
	res = prep_kerberos_and_kinit (conn);
	if (res != ADCLI_SUCCESS)
		return res;

	/* - And finally authenticate */
	res = authenticate_to_directory (conn);
	if (res != ADCLI_SUCCESS)
		return res;

	lookup_short_name (conn);
	lookup_domain_sid (conn);
	lookup_is_writeable (conn);
	return ADCLI_SUCCESS;
}

adcli_conn *
adcli_conn_new (const char *domain_name)
{
	adcli_conn *conn;

	conn = calloc (1, sizeof (adcli_conn));
	return_val_if_fail (conn != NULL, NULL);

	conn->refs = 1;
	conn->logins_allowed = ADCLI_LOGIN_COMPUTER_ACCOUNT | ADCLI_LOGIN_USER_ACCOUNT;
	adcli_conn_set_domain_name (conn, domain_name);
	adcli_conn_set_use_ldaps (conn, false);
	return conn;
}

static void
conn_free (adcli_conn *conn)
{
	free (conn->domain_name);
	free (conn->domain_realm);
	free (conn->domain_controller);
	free (conn->domain_short);
	free (conn->default_naming_context);
	free (conn->configuration_naming_context);
	_adcli_strv_free (conn->supported_capabilities);
	_adcli_strv_free (conn->supported_sasl_mechs);

	free (conn->netbios_computer_name);
	free (conn->full_computer_name);
	free (conn->host_fqdn);
	free (conn->krb5_conf_dir);

	if (conn->krb5_conf_snippet) {
		unlink (conn->krb5_conf_snippet);
		free (conn->krb5_conf_snippet);
	}

	adcli_conn_set_login_user (conn, NULL);
	adcli_conn_set_user_password (conn, NULL);
	adcli_conn_set_password_func (conn, NULL, NULL, NULL);

	conn_clear_state (conn);
	no_more_disco (conn);

	free (conn);
}

adcli_conn *
adcli_conn_ref (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);

	conn->refs++;
	return conn;
}

void
adcli_conn_unref (adcli_conn *conn)
{
	if (conn == NULL)
		return;

	if (--(conn->refs) > 0)
		return;

	conn_free (conn);
}

const char *
adcli_conn_get_host_fqdn (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->host_fqdn;
}

void
adcli_conn_set_host_fqdn (adcli_conn *conn,
                          const char *value)
{
	return_if_fail (conn != NULL);
	_adcli_str_set (&conn->host_fqdn, value);
}

const char *
adcli_conn_get_netbios_computer_name (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->netbios_computer_name;
}

void
adcli_conn_set_netbios_computer_name (adcli_conn *conn,
                              const char *value)
{
	return_if_fail (conn != NULL);
	_adcli_str_set (&conn->netbios_computer_name, value);
}

const char *
adcli_conn_get_full_computer_name (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->full_computer_name;
}

void
adcli_conn_set_full_computer_name (adcli_conn *conn,
			      const char *value)
{
	return_if_fail (conn != NULL);
	_adcli_str_set (&conn->full_computer_name, value);
}

const char *
adcli_conn_get_computer_password (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->computer_password;
}

void
adcli_conn_set_computer_password (adcli_conn *conn,
                                  const char *password)
{
	char *newval = NULL;

	return_if_fail (conn != NULL);

	if (password) {
		newval = strdup (password);
		return_if_fail (newval != NULL);
	}

	if (conn->computer_password)
		_adcli_password_free (conn->computer_password);

	conn->computer_password = newval;
}

const char *
adcli_conn_get_domain_name (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->domain_name;
}

void
adcli_conn_set_domain_name (adcli_conn *conn,
                            const char *value)
{
	return_if_fail (conn != NULL);
	_adcli_str_set (&conn->domain_name, value);
	no_more_disco (conn);
}

const char *
adcli_conn_get_domain_realm (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->domain_realm;
}

void
adcli_conn_set_domain_realm (adcli_conn *conn,
                             const char *value)
{
	return_if_fail (conn != NULL);
	_adcli_str_set (&conn->domain_realm, value);
	no_more_disco (conn);
}

const char *
adcli_conn_get_domain_controller (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->domain_controller;
}

void
adcli_conn_set_domain_controller (adcli_conn *conn,
                                  const char *value)
{
	return_if_fail (conn != NULL);
	_adcli_str_set (&conn->domain_controller, value);
	no_more_disco (conn);
}

bool
adcli_conn_get_use_ldaps (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->use_ldaps;
}

void
adcli_conn_set_use_ldaps (adcli_conn *conn, bool value)
{
	return_if_fail (conn != NULL);
	conn->use_ldaps = value;
}

const char *
adcli_conn_get_domain_short (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->domain_short;
}

const char *
adcli_conn_get_domain_sid (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->domain_sid;
}


LDAP *
adcli_conn_get_ldap_connection (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->ldap;
}

krb5_context
adcli_conn_get_krb5_context (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return_val_if_fail (conn->k5 != NULL, NULL);
	return conn->k5;
}

void
adcli_conn_set_krb5_context (adcli_conn *conn,
                             krb5_context k5)
{
	return_if_fail (conn != NULL);

	if (conn->k5 != NULL) {
		krb5_free_context (conn->k5);
	}

	conn->k5 = k5;
}

const char *
adcli_conn_get_login_user (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->user_name;
}

void
adcli_conn_set_login_user (adcli_conn *conn,
                           const char *value)
{
	return_if_fail (conn != NULL);
	_adcli_str_set (&conn->user_name, value);
}

const char *
adcli_conn_get_user_password (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->user_password;
}

void
adcli_conn_set_user_password (adcli_conn *conn,
                               const char *value)
{
	return_if_fail (conn != NULL);
	_adcli_str_set (&conn->user_password, value);
}

void
adcli_conn_set_password_func (adcli_conn *conn,
                              adcli_password_func password_func,
                              void *data,
                              adcli_destroy_func destroy_data)
{
	return_if_fail (conn != NULL);

	if (conn->password_destroy)
		(conn->password_destroy) (conn->password_data);
	conn->password_func = password_func;
	conn->password_data = data;
	conn->password_destroy = destroy_data;
}

adcli_login_type
adcli_conn_get_login_type (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, ADCLI_LOGIN_UNKNOWN);
	return conn->login_type;
}

adcli_login_type
adcli_conn_get_allowed_login_types (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, ADCLI_LOGIN_UNKNOWN);
	return conn->logins_allowed;
}

void
adcli_conn_set_allowed_login_types (adcli_conn *conn,
                                    adcli_login_type types)
{
	return_if_fail (conn != NULL);
	conn->logins_allowed = types;
}

krb5_ccache
adcli_conn_get_login_ccache (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->ccache;
}

const char *
adcli_conn_get_login_ccache_name (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->login_ccache_name;
}

void
adcli_conn_set_login_ccache_name (adcli_conn *conn,
                                  const char *ccname)
{
	char *newval = NULL;

	return_if_fail (conn != NULL);

	if (ccname) {
		newval = strdup (ccname);
		return_if_fail (newval != NULL);
	}

	if (conn->login_ccache_name) {
		if (conn->login_ccache_name_is_krb5)
			krb5_free_string (conn->k5, conn->login_ccache_name);
		else
			free (conn->login_ccache_name);
	}

	if (conn->ccache) {
		krb5_cc_close (conn->k5, conn->ccache);
		conn->ccache = NULL;
	}

	conn->login_ccache_name = newval;
	conn->login_ccache_name_is_krb5 = 0;
}

const char *
adcli_conn_get_login_keytab_name (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->login_keytab_name;
}

void
adcli_conn_set_login_keytab_name (adcli_conn *conn,
                                  const char *ktname)
{
	char *newval = NULL;

	return_if_fail (conn != NULL);

	if (ktname) {
		newval = strdup (ktname);
		return_if_fail (newval != NULL);
	}

	if (conn->login_keytab_name) {
		if (conn->login_keytab_name_is_krb5)
			krb5_free_string (conn->k5, conn->login_keytab_name);
		else
			free (conn->login_keytab_name);
	}

	if (conn->keytab) {
		krb5_kt_close (conn->k5, conn->keytab);
		conn->keytab = NULL;
	}

	conn->login_keytab_name = newval;
	conn->login_keytab_name_is_krb5 = 0;
}

const char *
adcli_conn_get_default_naming_context (adcli_conn *conn)
{
	return conn->default_naming_context;
}

const char *
adcli_conn_get_krb5_conf_dir (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->krb5_conf_dir;
}

void
adcli_conn_set_krb5_conf_dir (adcli_conn *conn,
                              const char *value)
{
	return_if_fail (conn != NULL);
	_adcli_str_set (&conn->krb5_conf_dir, value);
}

int
adcli_conn_server_has_capability (adcli_conn *conn,
                                  const char *capability)
{
	int i;

	return_val_if_fail (conn != NULL, 0);
	return_val_if_fail (capability != NULL, 0);

	if (!conn->supported_capabilities)
		return 0;

	for (i = 0; conn->supported_capabilities[i] != NULL; i++) {
		if (strcmp (capability, conn->supported_capabilities[i]) == 0)
			return 1;
	}

	return 0;
}

bool
adcli_conn_server_has_sasl_mech (adcli_conn *conn,
                                 const char *mech)
{
	int i;

	return_val_if_fail (conn != NULL, false);
	return_val_if_fail (mech != NULL, false);

	if (!conn->supported_sasl_mechs)
		return false;

	for (i = 0; conn->supported_sasl_mechs[i] != NULL; i++) {
		if (strcasecmp (mech, conn->supported_sasl_mechs[i]) == 0)
			return true;
	}

	return false;
}

bool adcli_conn_is_writeable (adcli_conn *conn)
{
	if (conn->is_writeable == IS_UNKNOWN) {
		lookup_is_writeable (conn);
	}

	return (conn->is_writeable == IS_WRITEABLE);
}
