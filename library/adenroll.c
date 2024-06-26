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

#include "adenroll.h"
#include "adprivate.h"
#include "seq.h"

#include <gssapi/gssapi_krb5.h>
#include <krb5/krb5.h>
#include <ldap.h>
#include <sasl/sasl.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iconv.h>
#include <lber.h>

#ifndef SAMBA_DATA_TOOL
#define SAMBA_DATA_TOOL "/usr/bin/net"
#endif

static krb5_enctype v60_later_enctypes_fips[] = {
	ENCTYPE_AES256_CTS_HMAC_SHA1_96,
	ENCTYPE_AES128_CTS_HMAC_SHA1_96,
	0
};

static krb5_enctype v60_later_enctypes[] = {
	ENCTYPE_AES256_CTS_HMAC_SHA1_96,
	ENCTYPE_AES128_CTS_HMAC_SHA1_96,
	ENCTYPE_DES3_CBC_SHA1,
	ENCTYPE_ARCFOUR_HMAC,
	ENCTYPE_DES_CBC_MD5,
	ENCTYPE_DES_CBC_CRC,
	0
};

static krb5_enctype v51_earlier_enctypes[] = {
	ENCTYPE_DES_CBC_CRC,
	ENCTYPE_DES_CBC_MD5,
	ENCTYPE_ARCFOUR_HMAC,
	0
};

/* The following list containst all attributes handled by adcli, some are
 * read-only and the others can be written as well. To properly document the
 * required permissions each attribute which adcli tries to modify should have
 * a comment starting with ':ADPermissions:' and the related permissions in AD
 * on the same line. Multiple permissions can be seperated with a '*'. For all
 * other attribute a suitable comment is very welcome. */
static char *default_ad_ldap_attrs[] =  {
	"sAMAccountName", /* Only set during creation */
	"userPrincipalName",   /* :ADPermissions: Read/Write userPrincipal Name */
	"msDS-KeyVersionNumber", /* Manages by AD */
	"msDS-supportedEncryptionTypes", /* :ADPermissions: Read/Write msDS-SupportedEncryptionTypes */
	"dNSHostName", /* :ADPermissions: Read/Write dNSHostName * Read and write DNS host name attributes * Validated write to DNS host name */
	"servicePrincipalName", /* :ADPermissions: Read/Write servicePrincipalName * Validated write to service principal name */
	"operatingSystem", /* :ADPermissions: Read/Write Operating System */
	"operatingSystemVersion", /* :ADPermissions: Read/Write Operating System Version */
	"operatingSystemServicePack", /* :ADPermissions: Read/Write operatingSystemServicePack */
	"pwdLastSet", /* Managed by AD */
	"userAccountControl", /* :ADPermissions: Read/Write userAccountControl */
	"description", /* :ADPermissions: Read/Write Description */
	NULL,
};

struct _adcli_enroll {
	int refs;
	adcli_conn *conn;
	bool is_service;
	bool is_service_explicit;

	char *host_fqdn;
	int host_fqdn_explicit;
	char *netbios_computer_name;
	int netbios_computer_name_explicit;
	char *full_computer_name;
	int full_computer_name_explicit;
	char *computer_sam;
	char *computer_password;
	int computer_password_explicit;
	int reset_password;
	krb5_principal computer_principal;

	char *domain_ou;
	int domain_ou_validated;
	int domain_ou_explicit;
	char *computer_dn;
	char *computer_container;
	LDAPMessage *computer_attributes;

	char **service_names;
	char **service_principals;
	int service_principals_explicit;

	char **service_principals_to_add;
	char **service_principals_to_remove;

	char *user_principal;
	int user_princpal_generate;

	char *os_name;
	int os_name_explicit;
	char *os_version;
	int os_version_explicit;
	char *os_service_pack;
	int os_service_pack_explicit;

	krb5_kvno kvno;
	char *keytab_name;
	int keytab_name_is_krb5;
	krb5_keytab keytab;
	krb5_principal *keytab_principals;
	krb5_enctype *keytab_enctypes;
	int keytab_enctypes_explicit;
	unsigned int computer_password_lifetime;
	int computer_password_lifetime_explicit;
	char *samba_data_tool;
	bool trusted_for_delegation;
	int trusted_for_delegation_explicit;
	bool dont_expire_password;
	int dont_expire_password_explicit;
	bool account_disable;
	int account_disable_explicit;
	char *description;
	char **setattr;
	char **delattr;
};

static const char *
s_or_c (adcli_enroll *enroll)
{
	return enroll->is_service ? "service" : "computer";
}

static void
check_if_service (adcli_enroll *enroll,
                  LDAP *ldap,
                  LDAPMessage *results)
{
	char **objectclasses = NULL;

	objectclasses = _adcli_ldap_parse_values (ldap, results, "objectClass");
	enroll->is_service = _adcli_strv_has_ex (objectclasses,
	                                         "msDS-ManagedServiceAccount",
	                                         strcasecmp) == 1 ? true : false;
	_adcli_strv_free (objectclasses);
}

static adcli_result
ensure_host_fqdn (adcli_result res,
                  adcli_enroll *enroll)
{
	const char *fqdn;

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->host_fqdn) {
		_adcli_info ("Using fully qualified name: %s",
		             enroll->host_fqdn);
		return ADCLI_SUCCESS;
	}

	if (enroll->host_fqdn_explicit) {
		_adcli_info ("Not setting fully qualified name");
		return ADCLI_SUCCESS;
	}

	/* By default use our actual host name discovered during connecting */
	fqdn = adcli_conn_get_host_fqdn (enroll->conn);
	_adcli_str_set (&enroll->host_fqdn, fqdn);
	return ADCLI_SUCCESS;
}

static adcli_result
ensure_computer_name (adcli_result res,
                      adcli_enroll *enroll)
{
	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->netbios_computer_name ) {
		_adcli_info ("Enrolling %s name: %s",
		             s_or_c (enroll),
		             enroll->netbios_computer_name);
		return ADCLI_SUCCESS;
	}

	if (enroll->full_computer_name ) {
		_adcli_calc_netbios_name (enroll->full_computer_name, &enroll->netbios_computer_name, &enroll->full_computer_name);
		return ADCLI_SUCCESS;
	}

	if (enroll->host_fqdn) {
		_adcli_calc_netbios_name (enroll->host_fqdn, &enroll->netbios_computer_name, &enroll->full_computer_name);
		return ADCLI_SUCCESS;
	}

	_adcli_err ("No host name from which to determine the %s name",
		    s_or_c (enroll));
	return ADCLI_ERR_CONFIG;
}

static adcli_result
ensure_computer_sam (adcli_result res,
                     adcli_enroll *enroll)
{
	krb5_error_code code;
	krb5_context k5;

	if (res != ADCLI_SUCCESS)
		return res;

	free (enroll->computer_sam);
	enroll->computer_sam = NULL;

	if (asprintf (&enroll->computer_sam, "%s$", enroll->netbios_computer_name) < 0)
		return_unexpected_if_fail (enroll->computer_sam != NULL);

	k5 = adcli_conn_get_krb5_context (enroll->conn);
	return_unexpected_if_fail (k5 != NULL);

	if (enroll->computer_principal)
		krb5_free_principal (k5, enroll->computer_principal);
	enroll->computer_principal = NULL;

	code = _adcli_krb5_build_principal (k5, enroll->computer_sam,
	                                    adcli_conn_get_domain_realm (enroll->conn),
	                                    &enroll->computer_principal);
	return_unexpected_if_fail (code == 0);

	return ADCLI_SUCCESS;
}

typedef int (rand_filter) (char *password, int length);

static int
filter_sam_chars (char *password,
                       int length)
{
	int i, j;

	/*
	 * There are a couple of restrictions for characters in the
	 * sAMAccountName attribute value, for our purpose (random suffix)
	 * letters and numbers are sufficient.
	 */
	for (i = 0, j = 0; i < length; i++) {
		if (password[i] >= 48 && password[i] <= 122 &&
		    isalnum (password[i]))
			password[j++] = password[i];
	}

	/* return the number of valid characters remaining */
	return j;
}

static int
filter_password_chars (char *password,
                       int length)
{
	int i, j;

	/*
	 * The MS documentation says their servers only use ASCII characters
	 * between 32 and 122 inclusive. We do that as well, and filter out
	 * all other random characters. We also remove certain characters
	 * special for use in a shell.
	 */
	for (i = 0, j = 0; i < length; i++) {
		if (password[i] >= 32 && password[i] <= 122 &&
		    strchr (" !'\"$`", password[i]) == NULL)
			password[j++] = password[i];
	}

	/* return the number of valid characters remaining */
	return j;
}

static char *
generate_host_password  (adcli_enroll *enroll,
                         size_t length,
                         rand_filter *filter)
{
	char *password;
	krb5_context k5;
	krb5_error_code code;
	krb5_data buffer;
	int at;

	k5 = adcli_conn_get_krb5_context (enroll->conn);
	return_val_if_fail (k5 != NULL, NULL);

	password = malloc (length + 1);
	return_val_if_fail (password != NULL, NULL);

	at = 0;
	while (at != length) {
		buffer.length = length - at;
		buffer.data = password + at;

		code = krb5_c_random_make_octets (k5, &buffer);
		return_val_if_fail (code == 0, NULL);

		at += filter (buffer.data, buffer.length);
		assert (at <= length);
	}

	/* This null termination works around a bug in krb5 */
	password[length] = '\0';
	return password;
}

static adcli_result
ensure_computer_password (adcli_result res,
                      adcli_enroll *enroll)
{
	const int length = 120;

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->computer_password)
		return ADCLI_SUCCESS;

	if (enroll->reset_password) {
		assert (enroll->netbios_computer_name != NULL);
		enroll->computer_password = _adcli_calc_reset_password (enroll->netbios_computer_name);
		return_unexpected_if_fail (enroll->computer_password != NULL);
		_adcli_info ("Using default reset computer password");

	} else {
		enroll->computer_password = generate_host_password (enroll, length, filter_password_chars);
		return_unexpected_if_fail (enroll->computer_password != NULL);
		_adcli_info ("Generated %d character computer password", length);
	}


	return ADCLI_SUCCESS;
}

static adcli_result
ensure_default_service_names (adcli_enroll *enroll)
{
	int length = 0;

	if (enroll->service_names != NULL) {
		length = seq_count (enroll->service_names);

		/* Make sure there is no entry with an unexpected case. AD
		 * would not care but since the client side is case-sensitive
		 * we should make sure we use the expected spelling. */
		seq_remove_unsorted (enroll->service_names,
		                     &length, "host",
		                     (seq_compar)strcasecmp, free);
		seq_remove_unsorted (enroll->service_names,
		                     &length, "RestrictedKrbHost",
		                     (seq_compar)strcasecmp, free);
	}

	/* The default ones specified by MS */
	enroll->service_names = _adcli_strv_add (enroll->service_names,
	                                         strdup ("host"), &length);
	enroll->service_names = _adcli_strv_add (enroll->service_names,
	                                         strdup ("RestrictedKrbHost"), &length);
	return ADCLI_SUCCESS;
}

static adcli_result
ensure_service_names (adcli_result res,
                      adcli_enroll *enroll)
{
	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->service_names || enroll->service_principals)
		return ADCLI_SUCCESS;

	return ensure_default_service_names (enroll);
}

static adcli_result
add_service_names_to_service_principals (adcli_enroll *enroll)
{
	char *name;
	int length = 0;
	int i;

	if (enroll->service_principals != NULL) {
		length = seq_count (enroll->service_principals);
	}

	for (i = 0; enroll->service_names[i] != NULL; i++) {
		if (asprintf (&name, "%s/%s", enroll->service_names[i], enroll->netbios_computer_name) < 0)
			return_unexpected_if_reached ();
		enroll->service_principals = _adcli_strv_add_unique (enroll->service_principals,
		                                                     name, &length, false);

		if (enroll->host_fqdn) {
			if (asprintf (&name, "%s/%s", enroll->service_names[i], enroll->host_fqdn) < 0)
				return_unexpected_if_reached ();
			enroll->service_principals = _adcli_strv_add_unique (enroll->service_principals,
			                                                     name, &length, false);
		}
	}

	return ADCLI_SUCCESS;
}

static adcli_result
add_and_remove_service_principals (adcli_enroll *enroll)
{
	int length = 0;
	size_t c;
	const char **list;

	if (enroll->service_principals != NULL) {
		length = seq_count (enroll->service_principals);
	}

	list = adcli_enroll_get_service_principals_to_add (enroll);
	if (list != NULL) {
		for (c = 0; list[c] != NULL; c++) {
			enroll->service_principals = _adcli_strv_add_unique (enroll->service_principals,
			                                                     strdup (list[c]),
			                                                     &length, false);
			if (enroll->service_principals == NULL) {
				return ADCLI_ERR_UNEXPECTED;
			}
		}
	}

	list = adcli_enroll_get_service_principals_to_remove (enroll);
	if (list != NULL) {
		for (c = 0; list[c] != NULL; c++) {
			/* enroll->service_principals typically refects the
			 * order of the principal in the keytabm so it is not
			 * ordered. */
			_adcli_strv_remove_unsorted (enroll->service_principals,
			                             list[c], &length);
		}
	}

	return ADCLI_SUCCESS;
}

static adcli_result
ensure_service_principals (adcli_result res,
                           adcli_enroll *enroll)
{
	if (res != ADCLI_SUCCESS)
		return res;

	assert (enroll->keytab_principals == NULL);

	if (!enroll->service_principals) {
		assert (enroll->service_names != NULL);
		res = add_service_names_to_service_principals (enroll);
	}

	if (res == ADCLI_SUCCESS) {
		res = add_and_remove_service_principals (enroll);
	}

	return res;
}

static void enroll_clear_keytab_principals (adcli_enroll *enroll)
{
	krb5_context k5;
	size_t c;

	if (enroll->keytab_principals) {
		k5 = adcli_conn_get_krb5_context (enroll->conn);
		return_if_fail (k5 != NULL);

		for (c = 0; enroll->keytab_principals[c] != NULL; c++)
			krb5_free_principal (k5, enroll->keytab_principals[c]);

		free (enroll->keytab_principals);
		enroll->keytab_principals = NULL;
	}

	return;
}

static adcli_result
ensure_keytab_principals (adcli_result res,
                          adcli_enroll *enroll)
{
	krb5_context k5;
	krb5_error_code code;
	int count = 0;
	int at, i;

	/* Prepare the principals we're going to add to the keytab */

	if (!enroll->is_service) {
		return_unexpected_if_fail (enroll->service_principals);
		count = _adcli_strv_len (enroll->service_principals);
	}

	k5 = adcli_conn_get_krb5_context (enroll->conn);
	return_unexpected_if_fail (k5 != NULL);

	enroll_clear_keytab_principals (enroll);
	enroll->keytab_principals = calloc (count + 3, sizeof (krb5_principal));
	return_unexpected_if_fail (enroll->keytab_principals != NULL);
	at = 0;

	/* First add the principal for the computer account name */
	code = krb5_copy_principal (k5, enroll->computer_principal,
	                            &enroll->keytab_principals[at++]);
	return_unexpected_if_fail (code == 0);

	/* Next, optionally add the user principal */
	if (enroll->user_principal) {
		code = krb5_parse_name (k5, enroll->user_principal,
		                        &enroll->keytab_principals[at++]);
		if (code != 0) {
			if (code != 0) {
				_adcli_err ("Couldn't parse kerberos user principal: %s: %s",
				            enroll->user_principal,
				            krb5_get_error_message (k5, code));
				return ADCLI_ERR_CONFIG;
			}
		}
	}

	/* Now add the principals for all the various services */

	for (i = 0; i < count; i++) {
		code = _adcli_krb5_build_principal (k5, enroll->service_principals[i],
		                                    adcli_conn_get_domain_realm (enroll->conn),
		                                    &enroll->keytab_principals[at++]);
		if (code != 0) {
			_adcli_err ("Couldn't parse kerberos service principal: %s: %s",
			            enroll->service_principals[i],
			            krb5_get_error_message (k5, code));
			return ADCLI_ERR_CONFIG;
		}
	}

	return ADCLI_SUCCESS;
}

static adcli_result
ensure_user_principal (adcli_result res,
                       adcli_enroll *enroll)
{
	char *name;

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->user_princpal_generate) {
		name = strdup (enroll->netbios_computer_name);
		return_unexpected_if_fail (name != NULL);

		_adcli_str_down (name);

		assert (enroll->user_principal == NULL);
		if (asprintf (&enroll->user_principal, "host/%s@%s",
		              name, adcli_conn_get_domain_realm (enroll->conn)) < 0)
			return_unexpected_if_reached ();

		free (name);
	}

	if (enroll->user_principal)
		_adcli_info ("With user principal: %s", enroll->user_principal);

	return ADCLI_SUCCESS;
}

static adcli_result
lookup_computer_container (adcli_enroll *enroll,
                           LDAP *ldap)
{
	char *attrs[] = { enroll->is_service ? "otherWellKnownObjects"
	                                     : "wellKnownObjects", NULL };
	const char *prefix = enroll->is_service ? "B:32:1EB93889E40C45DF9F0C64D23BBB6237:"
	                                        : "B:32:AA312825768811D1ADED00C04FD8D5CD:";
	const char *filter = enroll->is_service ? "(&(objectClass=container)(cn=Managed Service Accounts))"
	                                        : "(&(objectClass=container)(cn=Computers))";
	int prefix_len;
	LDAPMessage *results;
	const char *base;
	char **values;
	int ret;
	int i;

	if (enroll->computer_container)
		return ADCLI_SUCCESS;

	base = enroll->domain_ou;
	if (base == NULL)
		base = adcli_conn_get_default_naming_context (enroll->conn);
	assert (base != NULL);

	ret = ldap_search_ext_s (ldap, base, LDAP_SCOPE_BASE,
	                         "(objectClass=*)", attrs, 0, NULL, NULL,
	                         NULL, -1, &results);

	if (ret == LDAP_NO_SUCH_OBJECT && enroll->domain_ou) {
		_adcli_err ("The organizational unit does not exist: %s", enroll->domain_ou);
		return enroll->domain_ou_explicit ? ADCLI_ERR_CONFIG : ADCLI_ERR_DIRECTORY;

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't lookup %s container: %s",
		                                   s_or_c (enroll), base);
	}

	values = _adcli_ldap_parse_values (ldap, results, attrs[0]);
	ldap_msgfree (results);

	prefix_len = strlen (prefix);
	for (i = 0; values && values[i]; i++) {
		if (strncmp (values[i], prefix, prefix_len) == 0) {
			enroll->computer_container = strdup (values[i] + prefix_len);
			return_unexpected_if_fail (enroll->computer_container != NULL);
			_adcli_info ("Found well known %s container at: %s",
			             s_or_c (enroll), enroll->computer_container);
			break;
		}
	}

	_adcli_strv_free (values);

	/* Try harder */
	if (!enroll->computer_container) {
		ret = ldap_search_ext_s (ldap, base, LDAP_SCOPE_BASE, filter,
		                         attrs, 0, NULL, NULL, NULL, -1, &results);
		if (ret == LDAP_SUCCESS) {
			enroll->computer_container = _adcli_ldap_parse_dn (ldap, results);
			if (enroll->computer_container) {
				_adcli_info ("Well known %s container not "
				             "found, but found suitable one at: %s",
				             s_or_c (enroll),
				             enroll->computer_container);
			}
		}

		ldap_msgfree (results);
	}

	if (!enroll->computer_container && enroll->domain_ou) {
		_adcli_warn ("Couldn't find a computer container in the ou, "
		             "creating computer account directly in: %s", enroll->domain_ou);
		enroll->computer_container = strdup (enroll->domain_ou);
		return_unexpected_if_fail (enroll->computer_container != NULL);
	}

	if (!enroll->computer_container) {
		_adcli_err ("Couldn't find location to create %s accounts",
		            s_or_c (enroll));
		return ADCLI_ERR_DIRECTORY;
	}

	return ADCLI_SUCCESS;
}

static adcli_result
calculate_computer_account (adcli_enroll *enroll,
                            LDAP *ldap)
{
	adcli_result res;

	assert (enroll->computer_dn == NULL);

	/* Now need to find or validate the computer container */
	res = lookup_computer_container (enroll, ldap);
	if (res != ADCLI_SUCCESS)
		return res;

	assert (enroll->computer_container);

	free (enroll->computer_dn);
	enroll->computer_dn = NULL;

	if (asprintf (&enroll->computer_dn, "CN=%s,%s", enroll->full_computer_name, enroll->computer_container) < 0)
		return_unexpected_if_reached ();

	_adcli_info ("Calculated %s account: %s",
	             s_or_c (enroll), enroll->computer_dn);
	return ADCLI_SUCCESS;
}

static adcli_result
calculate_enctypes (adcli_enroll *enroll, char **enctype)
{
	char *value = NULL;
	krb5_enctype *read_enctypes;
	krb5_enctype *new_enctypes;
	char *new_value = NULL;
	int is_2008_or_later;
	LDAP *ldap;

	*enctype = NULL;
	/*
	 * Because we're using a keytab we want the server to be aware of the
	 * encryption types supported on the client, because we can't dynamically
	 * use a new one that's thrown at us.
	 *
	 * If the encryption types are not explicitly set by the caller of this
	 * library, then see if the account already has some encryption types
	 * marked on it.
	 *
	 * If not, write our default set to the account.
	 *
	 * Note that Windows 2003 and earlier have a standard set of encryption
	 * types, and no msDS-supportedEncryptionTypes attribute.
	 */

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	return_unexpected_if_fail (ldap != NULL);

	is_2008_or_later = adcli_conn_server_has_capability (enroll->conn, ADCLI_CAP_V60_OID);

	/* In 2008 or later, use the msDS-supportedEncryptionTypes attribute */
	if (is_2008_or_later && enroll->computer_attributes != NULL) {
		value = _adcli_ldap_parse_value (ldap, enroll->computer_attributes,
		                                 "msDS-supportedEncryptionTypes");

		if (!enroll->keytab_enctypes_explicit && value != NULL) {
			read_enctypes = _adcli_krb5_parse_enctypes (value);
			if (read_enctypes == NULL) {
				_adcli_warn ("Invalid or unsupported encryption types are set on "
				             "the computer account (%s).", value);
			} else {
				free (enroll->keytab_enctypes);
				enroll->keytab_enctypes = read_enctypes;
			}
		}

	/* In 2003 or earlier, standard set of enc types */
	} else {
		value = _adcli_krb5_format_enctypes (v51_earlier_enctypes);
	}

	new_enctypes = adcli_enroll_get_permitted_keytab_enctypes (enroll);
	if (new_enctypes == NULL) {
		_adcli_warn ("No permitted encryption type found.");
		return ADCLI_ERR_UNEXPECTED;
	}

	new_value = _adcli_krb5_format_enctypes (new_enctypes);
	krb5_free_enctypes (adcli_conn_get_krb5_context (enroll->conn), new_enctypes);
	if (new_value == NULL) {
		free (value);
		_adcli_warn ("The encryption types desired are not available in active directory");
		return ADCLI_ERR_CONFIG;
	}

	/* If we already have this value, then don't need to update */
	if (value && strcmp (new_value, value) == 0) {
		free (value);
		free (new_value);
		return ADCLI_SUCCESS;
	}
	free (value);

	if (!is_2008_or_later) {
		free (new_value);
		_adcli_warn ("Server does not support setting encryption types");
		return ADCLI_SUCCESS;
	}

	*enctype = new_value;
	return ADCLI_SUCCESS;
}

static LDAPMod **
get_mods_for_attrs (adcli_enroll *enroll, int mod_op)
{
	size_t len;
	size_t c;
	char *end;
	LDAPMod **mods = NULL;

	len = _adcli_strv_len (enroll->setattr);
	if (len == 0) {
		return NULL;
	}

	mods = calloc (len + 1, sizeof (LDAPMod *));
	return_val_if_fail (mods != NULL, NULL);

	for (c = 0; c < len; c++) {
		end = strchr (enroll->setattr[c], '=');
		if (end == NULL) {
			ldap_mods_free (mods, 1);
			return NULL;
		}

		mods[c] = calloc (1, sizeof (LDAPMod));
		if (mods[c] == NULL) {
			ldap_mods_free (mods, 1);
			return NULL;
		}

		mods[c]->mod_op = mod_op;
		*end = '\0';
		mods[c]->mod_type = strdup (enroll->setattr[c]);
		*end = '=';
		mods[c]->mod_values = calloc (2, sizeof (char *));
		if (mods[c]->mod_type == NULL || mods[c]->mod_values == NULL) {
			ldap_mods_free (mods, 1);
			return NULL;
		}

		mods[c]->mod_values[0] = strdup (end + 1);
		if (mods[c]->mod_values[0] == NULL) {
			ldap_mods_free (mods, 1);
			return NULL;
		}
	}

	return mods;
}

static LDAPMod **
get_del_mods_for_attrs (adcli_enroll *enroll, int mod_op)
{
	size_t len;
	size_t c;
	LDAPMod **mods = NULL;

	len = _adcli_strv_len (enroll->delattr);
	if (len == 0) {
		return NULL;
	}

	mods = calloc (len + 1, sizeof (LDAPMod *));
	return_val_if_fail (mods != NULL, NULL);

	for (c = 0; c < len; c++) {
		mods[c] = calloc (1, sizeof (LDAPMod));
		if (mods[c] == NULL) {
			ldap_mods_free (mods, 1);
			return NULL;
		}

		mods[c]->mod_op = mod_op;
		mods[c]->mod_type = strdup (enroll->delattr[c]);
		mods[c]->mod_values = NULL;
		if (mods[c]->mod_type == NULL) {
			ldap_mods_free (mods, 1);
			return NULL;
		}
	}

	return mods;
}

static struct berval *get_unicode_pwd (char *pwd)
{
	iconv_t cd;
	size_t s;
	char *in = NULL;
	char *in_ptr;
	size_t in_size;
	size_t len;
	char *out = NULL;
	char *out_ptr;
	size_t out_size;
	struct berval *bv = NULL;

	if (pwd == NULL) {
		return NULL;
	}

	if (asprintf (&in, "\"%s\"",pwd) < 0) {
		return NULL;
	}
	in_ptr = in;
	len = in_size = strlen (in);

	out_size = 2*in_size;
	out = malloc (out_size * sizeof (char));
	out_ptr = out;

	cd = iconv_open ("UTF-16LE", "UTF-8");
	if (cd == (iconv_t) -1 ) {
		goto done;
	}

	s = iconv (cd, &in_ptr,  &in_size, &out_ptr, &out_size);
	if (s == (size_t) -1 || out_size != 0) {
		iconv_close (cd);
		goto done;
	}

	s = iconv (cd, NULL, NULL, &out_ptr, &out_size);
	if (s == (size_t) -1) {
		iconv_close (cd);
		goto done;
	}

	if (iconv_close (cd) != 0) {
		goto done;
	}

	bv = malloc (sizeof(struct berval));
	if (bv == NULL) {
		goto done;
	}

	bv->bv_len = 2*len;
	bv->bv_val = out;

done:
	free (in);
	if (bv == NULL) {
		free (out);
	}

	return bv;
}

static adcli_result
create_computer_account (adcli_enroll *enroll,
                         LDAP *ldap, int ldap_passwd)
{
	char *vals_objectClass[] = { enroll->is_service ? "msDS-ManagedServiceAccount" : "computer", NULL };
	LDAPMod objectClass = { LDAP_MOD_ADD, "objectClass", { vals_objectClass, } };
	char *vals_sAMAccountName[] = { enroll->computer_sam, NULL };
	LDAPMod sAMAccountName = { LDAP_MOD_ADD, "sAMAccountName", { vals_sAMAccountName, } };
	char *vals_userAccountControl[] = { "69632", NULL }; /* WORKSTATION_TRUST_ACCOUNT | DONT_EXPIRE_PASSWD */
	LDAPMod userAccountControl = { LDAP_MOD_ADD, "userAccountControl", { vals_userAccountControl, } };
	char *vals_supportedEncryptionTypes[] = { NULL, NULL };
	LDAPMod encTypes = { LDAP_MOD_ADD, "msDS-supportedEncryptionTypes", { vals_supportedEncryptionTypes, } };
	char *vals_dNSHostName[] = { enroll->host_fqdn, NULL };
	LDAPMod dNSHostName = { LDAP_MOD_ADD, "dNSHostName", { vals_dNSHostName, } };
	char *vals_operatingSystem[] = { enroll->os_name, NULL };
	LDAPMod operatingSystem = { LDAP_MOD_ADD, "operatingSystem", { vals_operatingSystem, } };
	char *vals_operatingSystemVersion[] = { enroll->os_version, NULL };
	LDAPMod operatingSystemVersion = { LDAP_MOD_ADD, "operatingSystemVersion", { vals_operatingSystemVersion, } };
	char *vals_operatingSystemServicePack[] = { enroll->os_service_pack, NULL };
	LDAPMod operatingSystemServicePack = { LDAP_MOD_ADD, "operatingSystemServicePack", { vals_operatingSystemServicePack, } };
	char *vals_userPrincipalName[] = { enroll->user_principal, NULL };
	LDAPMod userPrincipalName = { LDAP_MOD_ADD, "userPrincipalName", { vals_userPrincipalName, }, };
	LDAPMod servicePrincipalName = { LDAP_MOD_ADD, "servicePrincipalName", { enroll->service_principals, } };
	char *vals_description[] = { enroll->description, NULL };
	LDAPMod description = { LDAP_MOD_ADD, "description", { vals_description, }, };
	struct berval *vals_unicodePwd[] = { NULL, NULL };
	LDAPMod unicodePwd = { LDAP_MOD_ADD | LDAP_MOD_BVALUES, "unicodePwd", { NULL, } };

	char *val = NULL;

	int ret;
	size_t c;
	size_t m;
	uint32_t uac = UAC_WORKSTATION_TRUST_ACCOUNT | UAC_DONT_EXPIRE_PASSWORD ;
	char *uac_str = NULL;
	LDAPMod **extra_mods = NULL;

	LDAPMod *all_mods[] = {
		&objectClass,
		&sAMAccountName,
		&userAccountControl,
		&encTypes,
		&dNSHostName,
		&operatingSystem,
		&operatingSystemVersion,
		&operatingSystemServicePack,
		&userPrincipalName,
		&servicePrincipalName,
		&description,
		&unicodePwd,
		NULL
	};

	size_t mods_count = sizeof (all_mods) / sizeof (LDAPMod *);
	LDAPMod **mods;

	if (ldap_passwd) {
		_adcli_info ("Trying to set %s password with LDAP", s_or_c (enroll));

		vals_unicodePwd[0] = get_unicode_pwd (enroll->computer_password);
		if (vals_unicodePwd[0] == NULL) {
			return ADCLI_ERR_FAIL;
		}
		unicodePwd.mod_vals.modv_bvals = vals_unicodePwd;
	}

	if (adcli_enroll_get_trusted_for_delegation (enroll)) {
		uac |= UAC_TRUSTED_FOR_DELEGATION;
	}

	if (enroll->dont_expire_password_explicit
		       && !adcli_enroll_get_dont_expire_password (enroll)) {
		uac &= ~(UAC_DONT_EXPIRE_PASSWORD);
	}

	if (asprintf (&uac_str, "%d", uac) < 0) {
		ber_bvfree (vals_unicodePwd[0]);
		return_val_if_reached (ADCLI_ERR_UNEXPECTED);
	}
	vals_userAccountControl[0] = uac_str;

	ret = calculate_enctypes (enroll, &val);
	if (ret != ADCLI_SUCCESS) {
		free (uac_str);
		ber_bvfree (vals_unicodePwd[0]);
		return ret;
	}
	vals_supportedEncryptionTypes[0] = val;

	if (enroll->setattr != NULL) {
		extra_mods = get_mods_for_attrs (enroll, LDAP_MOD_ADD);
		if (extra_mods == NULL) {
			_adcli_err ("Failed to add setattr attributes, "
			            "just using defaults");
		}
	}

	mods = calloc (mods_count + seq_count (extra_mods) + 1, sizeof (LDAPMod *));
	return_val_if_fail (mods != NULL, ADCLI_ERR_UNEXPECTED);

	m = 0;
	for (c = 0; c < mods_count - 1; c++) {
		/* Skip empty LDAP sttributes */
		if (all_mods[c]->mod_vals.modv_strvals != NULL && all_mods[c]->mod_vals.modv_strvals[0] != NULL) {
			mods[m++] = all_mods[c];
		}
	}

	for (c = 0; c < seq_count (extra_mods); c++) {
		mods[m++] = extra_mods[c];
	}
	mods[m] = NULL;

	ret = ldap_add_ext_s (ldap, enroll->computer_dn, mods, NULL, NULL);
	ber_bvfree (vals_unicodePwd[0]);
	ldap_mods_free (extra_mods, 1);
	free (mods);
	free (uac_str);
	free (val);

	/*
	 * Hand to head. This is really dumb... AD returns
	 * OBJECT_CLASS_VIOLATION when the 'admin' account doesn't have
	 * enough permission to create this computer account.
	 *
	 * Additionally LDAP_UNWILLING_TO_PERFORM and LDAP_CONSTRAINT_VIOLATION
	 * are seen on various Windows Servers as responses to this case.
	 *
	 * TODO: Perhaps some missing attributes are auto-generated when
	 * the administrative credentials have sufficient permissions, and
	 * those missing attributes cause the object class violation. However
	 * I've tried to screw around with this, and can't find the missing
	 * attributes. They may be hidden, like unicodePwd.
	 */

	if (ret == LDAP_INSUFFICIENT_ACCESS || ret == LDAP_OBJECT_CLASS_VIOLATION ||
	    ret == LDAP_UNWILLING_TO_PERFORM || ret == LDAP_CONSTRAINT_VIOLATION) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_CREDENTIALS,
		                                   "Insufficient permissions to modify computer account: %s",
		                                   enroll->computer_dn);

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't create computer account: %s",
		                                   enroll->computer_dn);
	}

	_adcli_info ("Created %s account: %s", s_or_c (enroll),
	                                       enroll->computer_dn);
	return ADCLI_SUCCESS;
}

static int
filter_for_necessary_updates (adcli_enroll *enroll,
                              LDAP *ldap,
                              LDAPMessage *entry,
                              LDAPMod **mods)
{
	struct berval **vals;
	int match;
	int out;
	int in;

	for (in = 0, out = 0; mods[in] != NULL; in++) {
		match = 0;

		/* Never update these attributes */
		if (strcasecmp (mods[in]->mod_type, "objectClass") == 0)
			continue;

		/* If no entry, then no filtering */
		if (entry != NULL) {
			vals = ldap_get_values_len (ldap, entry, mods[in]->mod_type);
			if (vals != NULL) {
				match = _adcli_ldap_have_in_mod (mods[in], vals);
				ldap_value_free_len (vals);
			}
		}

		if (!match)
			mods[out++] = mods[in];
	}

	mods[out] = NULL;
	return out;
}

static adcli_result
validate_computer_account (adcli_enroll *enroll,
                           int allow_overwrite,
                           int already_exists)
{
	assert (enroll->computer_dn != NULL);

	if (already_exists && !allow_overwrite) {
		_adcli_err ("The %s account %s already exists",
		            s_or_c (enroll), enroll->netbios_computer_name);
		return ADCLI_ERR_CONFIG;
	}

	/* Do we have an explicitly requested ou? */
	if (enroll->domain_ou && enroll->domain_ou_explicit && already_exists) {
		if (!_adcli_ldap_dn_has_ancestor (enroll->computer_dn, enroll->domain_ou)) {
			_adcli_err ("The %s account %s already exists, "
			            "but is not in the desired organizational unit.",
			            s_or_c (enroll), enroll->netbios_computer_name);
			return ADCLI_ERR_CONFIG;
		}
	}

	return ADCLI_SUCCESS;
}

static adcli_result
delete_computer_account (adcli_enroll *enroll,
                         LDAP *ldap)
{
	int ret;

	ret = ldap_delete_ext_s (ldap, enroll->computer_dn, NULL, NULL);
	if (ret == LDAP_INSUFFICIENT_ACCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_CREDENTIALS,
		                                   "Insufficient permissions to delete computer account: %s",
		                                   enroll->computer_dn);

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't delete computer account: %s",
		                                   enroll->computer_dn);
	} else {
		_adcli_info ("Deleted %s account at: %s", s_or_c (enroll),
		                                          enroll->computer_dn);
	}

	return ADCLI_SUCCESS;
}

static adcli_result
locate_computer_account (adcli_enroll *enroll,
                         LDAP *ldap,
                         bool use_fqdn,
                         LDAPMessage **rresults,
                         LDAPMessage **rentry)
{
	char *attrs[] = { "objectClass", "CN", NULL };
	LDAPMessage *results = NULL;
	LDAPMessage *entry = NULL;
	const char *base;
	char *value;
	char *filter;
	char *dn;
	int ret = 0;

	/* If we don't yet know our computer dn, then try and find it */
	if (use_fqdn) {
		return_unexpected_if_fail (enroll->host_fqdn != NULL);
		value = _adcli_ldap_escape_filter (enroll->host_fqdn);
		return_unexpected_if_fail (value != NULL);
		if (asprintf (&filter, "(&(objectClass=%s)(dNSHostName=%s))",
		              enroll->is_service ? "msDS-ManagedServiceAccount" : "computer",
		              value) < 0)
			return_unexpected_if_reached ();
	} else {
		value = _adcli_ldap_escape_filter (enroll->computer_sam);
		return_unexpected_if_fail (value != NULL);
		if (asprintf (&filter, "(&(objectClass=%s)(sAMAccountName=%s))",
		              enroll->is_service ? "msDS-ManagedServiceAccount" : "computer",
		              value) < 0)
			return_unexpected_if_reached ();
	}
	free (value);

	base = adcli_conn_get_default_naming_context (enroll->conn);
	ret = ldap_search_ext_s (ldap, base, LDAP_SCOPE_SUB, filter, attrs, 0,
	                         NULL, NULL, NULL, 1, &results);

	free (filter);

	/* ldap_search_ext_s() can return results *and* an error. */
	if (ret == LDAP_SUCCESS) {
		entry = ldap_first_entry (ldap, results);

		/* If we found a computer/service account, make note of dn */
		if (entry) {
			if (!enroll->is_service_explicit) {
				check_if_service ( enroll, ldap, results);
			}
			dn = ldap_get_dn (ldap, entry);
			free (enroll->computer_dn);
			enroll->computer_dn = strdup (dn);
			return_unexpected_if_fail (enroll->computer_dn != NULL);
			_adcli_info ("Found %s account for %s at: %s",
			             s_or_c (enroll),
			             use_fqdn ? enroll->host_fqdn
			                      : enroll->computer_sam, dn);
			ldap_memfree (dn);

		} else {
			ldap_msgfree (results);
			results = NULL;
			_adcli_info ("A %s account for %s does not exist",
			             s_or_c (enroll),
			             use_fqdn ? enroll->host_fqdn
			                      : enroll->computer_sam);
		}

	} else {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't lookup %s account: %s",
		                                   s_or_c (enroll),
		                                   use_fqdn ? enroll->host_fqdn
		                                            :enroll->computer_sam);
	}

	if (rresults)
		*rresults = results;
	else
		ldap_msgfree (results);
	if (rentry) {
		assert (rresults != NULL);
		*rentry = entry;
	}

	return ADCLI_SUCCESS;
}

static adcli_result
load_computer_account (adcli_enroll *enroll,
                       LDAP *ldap,
                       LDAPMessage **rresults,
                       LDAPMessage **rentry)
{
	char *attrs[] = { "objectClass", NULL };
	LDAPMessage *results = NULL;
	LDAPMessage *entry = NULL;
	int ret;

	ret = ldap_search_ext_s (ldap, enroll->computer_dn, LDAP_SCOPE_BASE,
	                         "(objectClass=computer)", attrs, 0,
	                         NULL, NULL, NULL, -1, &results);

	if (ret == LDAP_SUCCESS) {
		entry = ldap_first_entry (ldap, results);
		if (entry) {
			check_if_service (enroll, ldap, results);
			_adcli_info ("Found %s account for %s at: %s",
			             s_or_c (enroll),
			             enroll->computer_sam, enroll->computer_dn);
		}

	} else if (ret == LDAP_NO_SUCH_OBJECT) {
		results = entry = NULL;

	} else {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't check computer account: %s",
		                                   enroll->computer_dn);
	}

	if (rresults)
		*rresults = results;
	else
		ldap_msgfree (results);
	if (rentry) {
		assert (rresults != NULL);
		*rentry = entry;
	}

	return ADCLI_SUCCESS;
}

static adcli_result
refresh_service_account_name_sam_and_princ (adcli_enroll *enroll,
                                            const char *name)
{
	adcli_result res;

	adcli_enroll_set_netbios_computer_name (enroll, name);
	res = ensure_computer_sam (ADCLI_SUCCESS, enroll);
	res = ensure_keytab_principals (res, enroll);

	return res;
}

static adcli_result
calculate_random_service_account_name (adcli_enroll *enroll)
{
	char *suffix;
	char *new_name;
	int ret;
	adcli_result res;

	suffix = generate_host_password (enroll, 3, filter_sam_chars);
	return_unexpected_if_fail (suffix != NULL);

	ret = asprintf (&new_name, "%s!%s", enroll->netbios_computer_name, suffix);
	free (suffix);
	return_unexpected_if_fail (ret > 0);

	res = refresh_service_account_name_sam_and_princ (enroll, new_name);
	free (new_name);

	return res;
}

static adcli_result
get_service_account_name_from_ldap (adcli_enroll *enroll, LDAPMessage *results)
{
	LDAP *ldap;
	char *cn;
	adcli_result res;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	cn = _adcli_ldap_parse_value (ldap, results, "CN");
	return_unexpected_if_fail (cn != NULL);

	res = refresh_service_account_name_sam_and_princ (enroll, cn);
	free (cn);

	return res;
}

static adcli_result
locate_or_create_computer_account (adcli_enroll *enroll,
                                   int allow_overwrite, int ldap_passwd)
{
	LDAPMessage *results = NULL;
	LDAPMessage *entry = NULL;
	adcli_result res;
	int searched = 0;
	LDAP *ldap;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	/* Try to find the computer account */
	if (!enroll->computer_dn) {
		res = locate_computer_account (enroll, ldap, false,
		                               &results, &entry);
		if (res != ADCLI_SUCCESS)
			return res;
		searched = 1;
	}

	/* Try with fqdn for service accounts */
	if (!enroll->computer_dn && enroll->is_service
	                && enroll->host_fqdn != NULL) {
		res = locate_computer_account (enroll, ldap, true,
		                               &results, &entry);
		if (res != ADCLI_SUCCESS)
			return res;
		searched = 1;

		if (results != NULL) {
			res = get_service_account_name_from_ldap (enroll,
			                                          results);
			if (res != ADCLI_SUCCESS) {
				return res;
			}
		}
	}

	/* Next try and come up with where we think it should be */
	if (enroll->computer_dn == NULL) {
		if (enroll->is_service && !enroll->netbios_computer_name_explicit) {
			res = calculate_random_service_account_name (enroll);
			if (res != ADCLI_SUCCESS) {
				return res;
			}
		}
		res = calculate_computer_account (enroll, ldap);
		if (res != ADCLI_SUCCESS)
			return res;
	}

	assert (enroll->computer_dn != NULL);

	/* Have we seen an account yet? */
	if (!searched) {
		res = load_computer_account (enroll, ldap, &results, &entry);
		if (res != ADCLI_SUCCESS)
			return res;
	}

	res = validate_computer_account (enroll, allow_overwrite, entry != NULL);
	if (res == ADCLI_SUCCESS && entry == NULL)
		res = create_computer_account (enroll, ldap, ldap_passwd);

	/* Service account already exists, just continue and update the
	 * password */
	if (enroll->is_service && entry != NULL) {
		res = ADCLI_SUCCESS;
	}

	if (results)
		ldap_msgfree (results);

	return res;
}

static adcli_result
set_password_with_ldap (adcli_enroll *enroll)
{
	LDAP *ldap;
	int ret;
	struct berval *vals_unicodePwd[] = { NULL, NULL };
	LDAPMod unicodePwd = { LDAP_MOD_REPLACE | LDAP_MOD_BVALUES, "unicodePwd", { NULL, } };

	LDAPMod *all_mods[] = {
		&unicodePwd,
		NULL
	};

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	return_unexpected_if_fail (ldap != NULL);

	vals_unicodePwd[0] = get_unicode_pwd (enroll->computer_password);
	return_unexpected_if_fail (vals_unicodePwd[0] != NULL);
	unicodePwd.mod_vals.modv_bvals = vals_unicodePwd;

	_adcli_info ("Trying to set %s password with LDAP", s_or_c (enroll));

	ret = ldap_modify_ext_s (ldap, enroll->computer_dn, all_mods, NULL, NULL);
	ber_bvfree (vals_unicodePwd[0]);

	if (ret == LDAP_INSUFFICIENT_ACCESS || ret == LDAP_OBJECT_CLASS_VIOLATION ||
	    ret == LDAP_UNWILLING_TO_PERFORM || ret == LDAP_CONSTRAINT_VIOLATION) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_CREDENTIALS,
		                                   "Insufficient permissions to set password for: %s",
		                                   enroll->computer_dn);

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't set password for: %s",
		                                   enroll->computer_dn);
	}

	_adcli_info ("Set password for: %s", enroll->computer_dn);
	return ADCLI_SUCCESS;
}

static adcli_result
set_password_with_user_creds (adcli_enroll *enroll)
{
	krb5_error_code code;
	krb5_ccache ccache;
	krb5_context k5;
	krb5_data result_string = { 0, };
	krb5_data result_code_string = { 0, };
	adcli_result res;
	int result_code;
	char *message;

	assert (enroll->computer_password != NULL);
	assert (enroll->computer_principal != NULL);

	k5 = adcli_conn_get_krb5_context (enroll->conn);
	return_unexpected_if_fail (k5 != NULL);

	ccache = adcli_conn_get_login_ccache (enroll->conn);
	return_unexpected_if_fail (ccache != NULL);

	memset (&result_string, 0, sizeof (result_string));
	memset (&result_code_string, 0, sizeof (result_code_string));

	_adcli_info ("Trying to set %s password with Kerberos", s_or_c (enroll));

	code = krb5_set_password_using_ccache (k5, ccache, enroll->computer_password,
	                                       enroll->computer_principal, &result_code,
	                                       &result_code_string, &result_string);

	if (code != 0) {
		_adcli_err ("Couldn't set password for %s account: %s: %s",
		            s_or_c (enroll),
		            enroll->computer_sam, krb5_get_error_message (k5, code));
		/* TODO: Parse out these values */
		res = ADCLI_ERR_DIRECTORY;

	} else if (result_code != 0) {
#ifdef HAVE_KRB5_CHPW_MESSAGE
		if (krb5_chpw_message (k5, &result_string, &message) != 0)
			message = NULL;
#else
		message = NULL;
		if (result_string.length)
			message = _adcli_str_dupn (result_string.data, result_string.length);
#endif
		_adcli_err ("Cannot set %s password: %.*s%s%s",
		            s_or_c (enroll),
		            (int)result_code_string.length, result_code_string.data,
		            message ? ": " : "", message ? message : "");
		res = ADCLI_ERR_CREDENTIALS;
#ifdef HAVE_KRB5_CHPW_MESSAGE
		krb5_free_string (k5, message);
#else
		free (message);
#endif
	} else {
		_adcli_info ("Set %s password", s_or_c (enroll));
		if (enroll->kvno > 0) {
			enroll->kvno++;
			_adcli_info ("kvno incremented to %d", enroll->kvno);
		}
		res = ADCLI_SUCCESS;
	}

	krb5_free_data_contents (k5, &result_string);
	krb5_free_data_contents (k5, &result_code_string);

	return res;
}

static adcli_result
set_password_with_computer_creds (adcli_enroll *enroll)
{
	krb5_error_code code;
	krb5_creds creds;
	krb5_data result_string = { 0, };
	krb5_data result_code_string = { 0, };
	krb5_context k5;
	int result_code;
	adcli_result res;
	char *message;

	memset (&creds, 0, sizeof (creds));

	k5 = adcli_conn_get_krb5_context (enroll->conn);
	return_unexpected_if_fail (k5 != NULL);

	_adcli_info ("Trying to change %s password with Kerberos", s_or_c (enroll));

	code = _adcli_kinit_computer_creds (enroll->conn, "kadmin/changepw", NULL, &creds);
	if (code != 0) {
		_adcli_err ("Couldn't get change password ticket for %s account: %s: %s",
		            s_or_c (enroll),
		            enroll->computer_sam, krb5_get_error_message (k5, code));
		return ADCLI_ERR_DIRECTORY;
	}

	code = krb5_change_password (k5, &creds, enroll->computer_password,
	                             &result_code, &result_code_string, &result_string);

	krb5_free_cred_contents (k5, &creds);

	if (code != 0) {
		_adcli_err ("Couldn't change password for %s account: %s: %s",
		            s_or_c (enroll),
		            enroll->computer_sam, krb5_get_error_message (k5, code));
		/* TODO: Parse out these values */
		res = ADCLI_ERR_DIRECTORY;

	} else if (result_code != 0) {
#ifdef HAVE_KRB5_CHPW_MESSAGE
		if (krb5_chpw_message (k5, &result_string, &message) != 0)
			message = NULL;
#else
		message = NULL;
		if (result_string.length)
			message = _adcli_str_dupn (result_string.data, result_string.length);
#endif
		_adcli_err ("Cannot change computer password: %.*s%s%s",
		            (int)result_code_string.length, result_code_string.data,
		            message ? ": " : "", message ? message : "");
		res = ADCLI_ERR_CREDENTIALS;
#ifdef HAVE_KRB5_CHPW_MESSAGE
		krb5_free_string (k5, message);
#else
		free (message);
#endif
	} else {
		_adcli_info ("Changed computer password");
		if (enroll->kvno > 0) {
			enroll->kvno++;
		        _adcli_info ("kvno incremented to %d", enroll->kvno);
		}
		res = ADCLI_SUCCESS;
	}

	krb5_free_data_contents (k5, &result_string);
	krb5_free_data_contents (k5, &result_code_string);

	return res;
}

static adcli_result
set_computer_password (adcli_enroll *enroll, int ldap_passwd)
{
	if (ldap_passwd) {
		return set_password_with_ldap (enroll);
	}

	if (adcli_conn_get_login_type (enroll->conn) == ADCLI_LOGIN_COMPUTER_ACCOUNT)
		return set_password_with_computer_creds (enroll);
	else
		return set_password_with_user_creds (enroll);
}

static adcli_result
retrieve_computer_account (adcli_enroll *enroll)
{
	adcli_result res = ADCLI_SUCCESS;
	unsigned long kvno;
	char *value;
	LDAP *ldap;
	char *end;
	int ret;

	assert (enroll->computer_dn != NULL);
	assert (enroll->computer_attributes == NULL);

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	ret = ldap_search_ext_s (ldap, enroll->computer_dn, LDAP_SCOPE_BASE,
	                         "(objectClass=*)", default_ad_ldap_attrs,
	                         0, NULL, NULL, NULL, -1,
	                         &enroll->computer_attributes);

	if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't retrieve %s account info: %s",
		                                   s_or_c (enroll),
		                                   enroll->computer_dn);
	}

	/* Update the kvno */
	if (enroll->kvno == 0) {
		value = _adcli_ldap_parse_value (ldap, enroll->computer_attributes, "msDS-KeyVersionNumber");
		if (value != NULL) {
			kvno = strtoul (value, &end, 10);
			if (end == NULL || *end != '\0') {
				_adcli_err ("Invalid kvno '%s' for %s account in directory: %s",
				            value, s_or_c (enroll), enroll->computer_dn);
				res = ADCLI_ERR_DIRECTORY;

			} else {
				enroll->kvno = kvno;

				_adcli_info ("Retrieved kvno '%s' for %s account in directory: %s",
				             value, s_or_c (enroll), enroll->computer_dn);
			}

			free (value);

		} else {
			/* Apparently old AD didn't have this attribute, use zero */
			enroll->kvno = 0;

			_adcli_info ("No kvno found for %s account in directory: %s",
			             s_or_c (enroll), enroll->computer_dn);
		}
	}

	return res;
}

static adcli_result
update_and_calculate_enctypes (adcli_enroll *enroll)
{
	char *vals_supportedEncryptionTypes[] = { NULL, NULL };
	LDAPMod mod = { LDAP_MOD_REPLACE, "msDS-supportedEncryptionTypes", { vals_supportedEncryptionTypes, } };
	LDAPMod *mods[2] = { &mod, NULL };
	char *new_value;
	LDAP *ldap;
	int ret;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	return_unexpected_if_fail (ldap != NULL);

	ret = calculate_enctypes (enroll, &new_value);
	if (ret != ADCLI_SUCCESS) {
		free (new_value);
		return ret;
	}

	if (new_value == NULL) {
		return ADCLI_SUCCESS;
	}

	vals_supportedEncryptionTypes[0] = new_value;

	if (filter_for_necessary_updates (enroll, ldap, enroll->computer_attributes, mods) == 0)
		ret = 0;
	else
		ret = ldap_modify_ext_s (ldap, enroll->computer_dn, mods, NULL, NULL);

	free (new_value);

	if (ret == LDAP_INSUFFICIENT_ACCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_CREDENTIALS,
		                                   "Insufficient permissions to set encryption types on %s account: %s",
		                                   s_or_c (enroll),
		                                   enroll->computer_dn);

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't set encryption types on %s account: %s",
		                                   s_or_c (enroll),
		                                   enroll->computer_dn);
	}

	return ADCLI_SUCCESS;
}

static adcli_result
update_computer_attribute (adcli_enroll *enroll,
                           LDAP *ldap,
                           LDAPMod **mods)
{
	adcli_result res = ADCLI_SUCCESS;
	char *string;
	int ret;

	/* See if there are any changes to be made? */
	if (filter_for_necessary_updates (enroll, ldap, enroll->computer_attributes, mods) == 0)
		return ADCLI_SUCCESS;

	string = _adcli_ldap_mods_to_string (mods);
	return_unexpected_if_fail (string != NULL);

	_adcli_info ("Modifying %s account: %s", s_or_c (enroll), string);

	ret = ldap_modify_ext_s (ldap, enroll->computer_dn, mods, NULL, NULL);

	if (ret != LDAP_SUCCESS) {
		_adcli_warn ("Couldn't set %s on %s account: %s: %s",
		             string, s_or_c (enroll), enroll->computer_dn,
		             ldap_err2string (ret));
		res = ADCLI_ERR_DIRECTORY;
	}

	free (string);
	return res;
}

static char *get_user_account_control (adcli_enroll *enroll)
{
	uint32_t uac = 0;
	unsigned long attr_val;
	char *uac_str;
	LDAP *ldap;
	char *end;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	return_val_if_fail (ldap != NULL, NULL);

	uac_str = _adcli_ldap_parse_value (ldap, enroll->computer_attributes, "userAccountControl");
	if (uac_str != NULL) {

		attr_val = strtoul (uac_str, &end, 10);
		if (*end != '\0' || attr_val > UINT32_MAX) {
			_adcli_warn ("Invalid userAccountControl '%s' for %s account in directory: %s, assuming 0",
			            uac_str, s_or_c (enroll), enroll->computer_dn);
		} else {
			uac = attr_val;
		}
		free (uac_str);
	}

	if (uac == 0) {
		uac = UAC_WORKSTATION_TRUST_ACCOUNT | UAC_DONT_EXPIRE_PASSWORD;
	}

	if (enroll->trusted_for_delegation_explicit) {
		if (adcli_enroll_get_trusted_for_delegation (enroll)) {
			uac |= UAC_TRUSTED_FOR_DELEGATION;
		} else {
			uac &= ~(UAC_TRUSTED_FOR_DELEGATION);
		}
	}

	if (enroll->dont_expire_password_explicit) {
		if (adcli_enroll_get_dont_expire_password (enroll)) {
			uac |= UAC_DONT_EXPIRE_PASSWORD;
		} else {
			uac &= ~(UAC_DONT_EXPIRE_PASSWORD);
		}
	}

	if (enroll->account_disable_explicit) {
		if (adcli_enroll_get_account_disable (enroll)) {
			uac |= UAC_ACCOUNTDISABLE;
		} else {
			uac &= ~(UAC_ACCOUNTDISABLE);
		}
	}

	if (asprintf (&uac_str, "%d", uac) < 0) {
		return_val_if_reached (NULL);
	}

	return uac_str;
}

static void
update_computer_account (adcli_enroll *enroll)
{
	int res = 0;
	LDAP *ldap;
	char *value = NULL;

	/* No updates for service accounts */
	if (enroll->is_service) {
		return;
	}

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	return_if_fail (ldap != NULL);

	/* Only update attributes which are explicitly given on the command
	 * line or not set in the existing AD object. Otherwise 'adcli update'
	 * must be always called with the same set of options to make sure
	 * existing attributes are not deleted or overwritten with different
	 * values. */
	if (enroll->computer_attributes != NULL) {
		value = _adcli_ldap_parse_value (ldap,
		                                 enroll->computer_attributes,
		                                 "dNSHostName");
	}
	if (enroll->host_fqdn_explicit || value == NULL ) {
		char *vals_dNSHostName[] = { enroll->host_fqdn, NULL };
		LDAPMod dNSHostName = { LDAP_MOD_REPLACE, "dNSHostName", { vals_dNSHostName, } };
		LDAPMod *mods[] = { &dNSHostName, NULL };

		res |= update_computer_attribute (enroll, ldap, mods);
	}
	free (value);

	if (res == ADCLI_SUCCESS && (enroll->trusted_for_delegation_explicit ||
	                             enroll->dont_expire_password_explicit ||
	                             enroll->account_disable_explicit)) {
		char *vals_userAccountControl[] = { NULL , NULL };
		LDAPMod userAccountControl = { LDAP_MOD_REPLACE, "userAccountControl", { vals_userAccountControl, } };
		LDAPMod *mods[] = { &userAccountControl, NULL };

		vals_userAccountControl[0] = get_user_account_control (enroll);
		if (vals_userAccountControl[0] != NULL) {
			res |= update_computer_attribute (enroll, ldap, mods);
		} else {
			_adcli_warn ("Cannot update userAccountControl");
		}
	}

	if (res == ADCLI_SUCCESS) {
		char *vals_operatingSystem[] = { enroll->os_name, NULL };
		LDAPMod operatingSystem = { LDAP_MOD_REPLACE, "operatingSystem", { vals_operatingSystem, } };
		char *vals_operatingSystemVersion[] = { enroll->os_version, NULL };
		LDAPMod operatingSystemVersion = { LDAP_MOD_REPLACE, "operatingSystemVersion", { vals_operatingSystemVersion, } };
		char *vals_operatingSystemServicePack[] = { enroll->os_service_pack, NULL };
		LDAPMod operatingSystemServicePack = { LDAP_MOD_REPLACE, "operatingSystemServicePack", { vals_operatingSystemServicePack, } };
		LDAPMod *mods[] = { NULL, NULL, NULL, NULL };
		size_t c = 0;

		if (enroll->os_name_explicit) {
			mods[c++] = &operatingSystem;
		}
		if (enroll->os_version_explicit) {
			mods[c++] = &operatingSystemVersion;
		}
		if (enroll->os_service_pack_explicit) {
			mods[c++] = &operatingSystemServicePack;
		}

		if (c != 0) {
			res |= update_computer_attribute (enroll, ldap, mods);
		}
	}

	if (res == ADCLI_SUCCESS && enroll->user_principal != NULL && !enroll->user_princpal_generate) {
		char *vals_userPrincipalName[] = { enroll->user_principal, NULL };
		LDAPMod userPrincipalName = { LDAP_MOD_REPLACE, "userPrincipalName", { vals_userPrincipalName, }, };
		LDAPMod *mods[] = { &userPrincipalName, NULL, };

		res |= update_computer_attribute (enroll, ldap, mods);
	}

	if (res == ADCLI_SUCCESS && enroll->description != NULL) {
		char *vals_description[] = { enroll->description, NULL };
		LDAPMod description = { LDAP_MOD_REPLACE, "description", { vals_description, }, };
		LDAPMod *mods[] = { &description, NULL, };

		res |= update_computer_attribute (enroll, ldap, mods);
	}

	if (res == ADCLI_SUCCESS && enroll->setattr != NULL) {
		LDAPMod **mods = get_mods_for_attrs (enroll, LDAP_MOD_REPLACE);
		if (mods != NULL) {
			res |= update_computer_attribute (enroll, ldap, mods);
			ldap_mods_free (mods, 1);
		}
	}

	if (res == ADCLI_SUCCESS && enroll->delattr != NULL) {
		LDAPMod **mods = get_del_mods_for_attrs (enroll, LDAP_MOD_DELETE);
		if (mods != NULL) {
			res |= update_computer_attribute (enroll, ldap, mods);
			ldap_mods_free (mods, 1);
		}
	}

	if (res != 0)
		_adcli_info ("Updated existing computer account: %s", enroll->computer_dn);
}

static adcli_result
update_service_principals (adcli_enroll *enroll)
{
	LDAPMod servicePrincipalName = { LDAP_MOD_REPLACE, "servicePrincipalName", { enroll->service_principals, } };
	LDAPMod *mods[] = { &servicePrincipalName, NULL, };
	LDAP *ldap;
	int ret;

	/* No updates for service accounts */
	if (enroll->is_service) {
		return ADCLI_SUCCESS;
	}

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	return_unexpected_if_fail (ldap != NULL);

	/* See if there are any changes to be made? */
	if (filter_for_necessary_updates (enroll, ldap, enroll->computer_attributes, mods) == 0)
		return ADCLI_SUCCESS;

	ret = ldap_modify_ext_s (ldap, enroll->computer_dn, mods, NULL, NULL);
	if (ret == LDAP_INSUFFICIENT_ACCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_CREDENTIALS,
		                                   "Insufficient permissions to set service principals on computer account: %s",
		                                   enroll->computer_dn);

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't set service principals on computer account %s",
		                                   enroll->computer_dn);
	}

	return ADCLI_SUCCESS;
}

static adcli_result
ensure_host_keytab (adcli_result res,
                    adcli_enroll *enroll)
{
	krb5_context k5;
	krb5_error_code code;
	char *name;

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->keytab)
		return ADCLI_SUCCESS;

	k5 = adcli_conn_get_krb5_context (enroll->conn);
	return_unexpected_if_fail (k5 != NULL);

	res = _adcli_krb5_open_keytab (k5, enroll->keytab_name, &enroll->keytab);
	if (res != ADCLI_SUCCESS)
		return res;

	if (!enroll->keytab_name) {
		name = malloc (MAX_KEYTAB_NAME_LEN + 1);
		return_unexpected_if_fail (name != NULL);

		code = krb5_kt_get_name (k5, enroll->keytab, name, MAX_KEYTAB_NAME_LEN + 1);
		return_unexpected_if_fail (code == 0);

		enroll->keytab_name = name;
		enroll->keytab_name_is_krb5 = 1;
	}

	_adcli_info ("Using keytab: %s", enroll->keytab_name);
	return ADCLI_SUCCESS;
}

static krb5_boolean
load_keytab_entry (krb5_context k5,
                   krb5_keytab_entry *entry,
                   void *data)
{
	adcli_enroll *enroll = data;
	krb5_error_code code;
	krb5_principal principal;
	const char *realm;
	size_t len;
	char *value;
	char *name;
	char *dom;

	/* Skip over any entry without a principal or realm */
	principal = entry->principal;
	if (!principal || !principal->realm.length)
		return TRUE;

	/* Use the first keytab entry as realm */
	realm = adcli_conn_get_domain_realm (enroll->conn);
	if (!realm) {
		value = _adcli_str_dupn (principal->realm.data, principal->realm.length);
		adcli_conn_set_domain_realm (enroll->conn, value);
		_adcli_info ("Found realm in keytab: %s", value);
		realm = adcli_conn_get_domain_realm (enroll->conn);
		free (value);
	}

	/* Only look at entries that match the realm */
	len = strlen (realm);
	if (principal->realm.length != len && strncmp (realm, principal->realm.data, len) != 0)
		return TRUE;

	code = krb5_unparse_name_flags (k5, principal, KRB5_PRINCIPAL_UNPARSE_NO_REALM, &name);
	return_val_if_fail (code == 0, FALSE);

	len = strlen (name);

	if (!enroll->service_principals_explicit) {
		if (!_adcli_strv_has (enroll->service_principals, name) && strchr (name, '/')) {
			value = strdup (name);
			return_val_if_fail (value != NULL, FALSE);
			_adcli_info ("Found service principal in keytab: %s", value);
			enroll->service_principals = _adcli_strv_add_unique (enroll->service_principals, value, NULL, false);
		}
	}

	if (!enroll->host_fqdn_explicit && !enroll->full_computer_name_explicit && !enroll->netbios_computer_name_explicit) {

		/* Automatically use the netbios name */
		if (!enroll->netbios_computer_name && len > 1 &&
		    _adcli_str_has_suffix (name, "$") && !strchr (name, '/')) {
			enroll->netbios_computer_name = name;
			name[len - 1] = '\0';
			_adcli_info ("Found %s name in keytab: %s",
			             s_or_c (enroll), name);
			adcli_conn_set_netbios_computer_name (enroll->conn,
			                                      enroll->netbios_computer_name);
			name = NULL;

		} else {
			dom = strchr (name, '.');
			if (!enroll->host_fqdn && _adcli_str_has_prefix (name, "host/") && dom) {
				/* Skip host/ prefix */
				enroll->host_fqdn = strdup (name + 5);
				return_val_if_fail (enroll->host_fqdn != NULL, FALSE);
				enroll->full_computer_name = strndup (name + 5, dom - name - 5);
				return_val_if_fail (enroll->full_computer_name != NULL, FALSE);
				_adcli_info ("Found host qualified name in keytab: %s", enroll->host_fqdn);
			}
		}
	}

	free (name);
	return TRUE;
}

static adcli_result
load_host_keytab (adcli_enroll *enroll)
{
	krb5_error_code code;
	adcli_result res;
	krb5_context k5;
	krb5_keytab keytab;

	res = _adcli_krb5_init_context (&k5);
	if (res != ADCLI_SUCCESS)
		return res;

	res = _adcli_krb5_open_keytab (k5, enroll->keytab_name, &keytab);
	if (res == ADCLI_SUCCESS) {
		code = _adcli_krb5_keytab_enumerate (k5, keytab, load_keytab_entry, enroll);
		if (code != 0) {
			_adcli_err ("Couldn't enumerate keytab: %s: %s",
		                    enroll->keytab_name, krb5_get_error_message (k5, code));
			res = ADCLI_ERR_FAIL;
		}
		krb5_kt_close (k5, keytab);
	}

	krb5_free_context (k5);
	return res;
}

typedef struct {
	krb5_kvno kvno;
	krb5_principal principal;
	int matched;
} match_principal_kvno;

static krb5_boolean
match_principal_and_kvno (krb5_context k5,
                          krb5_keytab_entry *entry,
                          void *data)
{
	match_principal_kvno *closure = data;

	assert (closure->principal);

	/*
	 * Don't match entries with kvno - 1 so that existing sessions
	 * will still work.
	 */

	if (entry->vno + 1 == closure->kvno)
		return 0;

	/* Is this the principal we're looking for? */
	if (krb5_principal_compare (k5, entry->principal, closure->principal)) {
		closure->matched = 1;
		return 1;
	}

	return 0;
}

#define DEFAULT_SALT 1

static krb5_data *
build_principal_salts (adcli_enroll *enroll,
                       krb5_context k5,
                       krb5_principal principal)
{
	krb5_error_code code;
	krb5_data *salts;
	const int count = 3;
	int i = 0;

	salts = calloc (count, sizeof (krb5_data));
	return_val_if_fail (salts != NULL, NULL);

	/* Build up the salts, first a standard kerberos salt */
	code = krb5_principal2salt (k5, principal, &salts[i++]);
	return_val_if_fail (code == 0, NULL);

	/* Then a Windows 2003 computer account salt */
	code = _adcli_krb5_w2k3_salt (k5, principal, enroll->netbios_computer_name, &salts[i++]);
	return_val_if_fail (code == 0, NULL);

	/* And lastly a null salt */
	salts[i++].data = NULL;

	assert (count == i);
	return salts;
}

static void
free_principal_salts (krb5_context k5,
                      krb5_data *salts)
{
	int i;

	for (i = 0; salts[i].data != NULL; i++)
		krb5_free_data_contents (k5, salts + i);

	free (salts);
}

static adcli_result
remove_principal_from_keytab (adcli_enroll *enroll,
                              krb5_context k5,
                              const char *principal_name)
{
	krb5_error_code code;
	krb5_principal principal;
	match_principal_kvno closure;

	code = _adcli_krb5_build_principal (k5, principal_name,
	                                    adcli_conn_get_domain_realm (enroll->conn),
	                                    &principal);
	if (code != 0) {
		_adcli_err ("Couldn't parse principal: %s: %s",
		            principal_name, krb5_get_error_message (k5, code));
		return ADCLI_ERR_FAIL;
	}

	closure.kvno = enroll->kvno;
	closure.principal = principal;
	closure.matched = 0;

	code = _adcli_krb5_keytab_clear (k5, enroll->keytab,
	                                 match_principal_and_kvno, &closure);
	krb5_free_principal (k5, principal);

	if (code != 0) {
		_adcli_err ("Couldn't update keytab: %s: %s",
		            enroll->keytab_name, krb5_get_error_message (k5, code));
		return ADCLI_ERR_FAIL;
	}

	return ADCLI_SUCCESS;
}

static adcli_result
add_principal_to_keytab (adcli_enroll *enroll,
                         krb5_context k5,
                         krb5_principal principal,
                         const char *principal_name,
                         int *which_salt,
                         adcli_enroll_flags flags)
{
	match_principal_kvno closure;
	krb5_data password;
	krb5_error_code code;
	krb5_data *salts;
	krb5_enctype *enctypes;

	/* Remove old stuff from the keytab for this principal */

	closure.kvno = enroll->kvno;
	closure.principal = principal;
	closure.matched = 0;

	code = _adcli_krb5_keytab_clear (k5, enroll->keytab,
	                                 match_principal_and_kvno, &closure);

	if (code != 0) {
		_adcli_err ("Couldn't update keytab: %s: %s",
		            enroll->keytab_name, krb5_get_error_message (k5, code));
		return ADCLI_ERR_FAIL;
	}

	if (closure.matched) {
		_adcli_info ("Cleared old entries from keytab: %s",
		             enroll->keytab_name);
	}

	enctypes = adcli_enroll_get_permitted_keytab_enctypes (enroll);
	if (enctypes == NULL) {
		_adcli_warn ("No permitted encryption type found.");
		return ADCLI_ERR_UNEXPECTED;
	}

	if (flags & ADCLI_ENROLL_PASSWORD_VALID) {
		code = _adcli_krb5_keytab_copy_entries (k5, enroll->keytab, principal,
		                                        enroll->kvno, enctypes);
	} else {

		password.data = enroll->computer_password;
		password.length = strlen (enroll->computer_password);

		/*
		 * So we need to discover which salt to use. As a side effect we are
		 * also testing that our account works.
		 */

		salts = build_principal_salts (enroll, k5, principal);
		if (salts == NULL) {
			krb5_free_enctypes (k5, enctypes);
			return ADCLI_ERR_UNEXPECTED;
		}

		if (*which_salt < 0) {
			code = _adcli_krb5_keytab_discover_salt (k5, principal, enroll->kvno, &password,
			                                         enctypes, salts, which_salt);
			if (code != 0) {
				_adcli_warn ("Couldn't authenticate with keytab while discovering which salt to use: %s: %s",
				             principal_name, krb5_get_error_message (k5, code));
				*which_salt = DEFAULT_SALT;
			} else {
				assert (*which_salt >= 0);
				_adcli_info ("Discovered which keytab salt to use");
			}
		}

		code = _adcli_krb5_keytab_add_entries (k5, enroll->keytab, principal,
		                                       enroll->kvno, &password, enctypes, &salts[*which_salt]);

		free_principal_salts (k5, salts);
	}
	krb5_free_enctypes (k5, enctypes);

	if (code != 0) {
		_adcli_err ("Couldn't add keytab entries: %s: %s",
		            enroll->keytab_name, krb5_get_error_message (k5, code));
		return ADCLI_ERR_FAIL;
	}


	_adcli_info ("Added the entries to the keytab: %s: %s",
	             principal_name, enroll->keytab_name);
	return ADCLI_SUCCESS;
}

static adcli_result
update_keytab_for_principals (adcli_enroll *enroll,
                              adcli_enroll_flags flags)
{
	krb5_context k5;
	adcli_result res;
	int which_salt = -1;
	char *name;
	int i;

	assert (enroll->keytab_principals != NULL);

	k5 = adcli_conn_get_krb5_context (enroll->conn);
	return_unexpected_if_fail (k5 != NULL);

	for (i = 0; enroll->keytab_principals[i] != 0; i++) {
		if (krb5_unparse_name (k5, enroll->keytab_principals[i], &name) != 0)
			name = "";
		res = add_principal_to_keytab (enroll, k5, enroll->keytab_principals[i],
		                               name, &which_salt, flags);
		krb5_free_unparsed_name (k5, name);

		if (res != ADCLI_SUCCESS)
			return res;
	}

	if (enroll->service_principals_to_remove != NULL) {
		for (i = 0; enroll->service_principals_to_remove[i] != NULL; i++) {
			res = remove_principal_from_keytab (enroll, k5,
			                                    enroll->service_principals_to_remove[i]);
			if (res != ADCLI_SUCCESS) {
				_adcli_warn ("Failed to remove %s from keytab.",
				             enroll->service_principals_to_remove[i]);
			}
		}
	}

	return ADCLI_SUCCESS;
}

static adcli_result
update_samba_data (adcli_enroll *enroll)
{
	int ret;
	char *argv_pw[] = { NULL, "changesecretpw", "-i", "-f", NULL };
	char *argv_sid[] = { NULL, "setdomainsid", NULL, NULL };

	argv_pw[0] = (char *) adcli_enroll_get_samba_data_tool (enroll);
	if (argv_pw[0] ==NULL) {
		_adcli_err ("Samba data tool not available.");
		return ADCLI_ERR_FAIL;
	}
	argv_sid[0] = argv_pw[0];

	argv_sid[2] = (char *) adcli_conn_get_domain_sid (enroll->conn);
	if (argv_sid[2] == NULL) {
		_adcli_err ("Domain SID not available.");
	} else {
		_adcli_info ("Trying to set domain SID %s for Samba.",
		             argv_sid[2]);
		ret = _adcli_call_external_program (argv_sid[0], argv_sid,
		                                    NULL, NULL, NULL);
		if (ret != ADCLI_SUCCESS) {
			_adcli_err ("Failed to set Samba domain SID.");
		}
	}

	_adcli_info ("Trying to set Samba secret.");
	ret = _adcli_call_external_program (argv_pw[0], argv_pw,
	                                    enroll->computer_password, NULL, NULL);
	if (ret != ADCLI_SUCCESS) {
		_adcli_err ("Failed to set Samba computer account password.");
	}

	return ret;
}

static void
enroll_clear_state (adcli_enroll *enroll)
{
	krb5_context k5;

	enroll_clear_keytab_principals (enroll);

	if (enroll->keytab) {
		k5 = adcli_conn_get_krb5_context (enroll->conn);
		return_if_fail (k5 != NULL);

		krb5_kt_close (k5, enroll->keytab);
		enroll->keytab = NULL;
	}

	free (enroll->computer_sam);
	enroll->computer_sam = NULL;

	if (enroll->computer_principal) {
		k5 = adcli_conn_get_krb5_context (enroll->conn);
		return_if_fail (k5 != NULL);

		krb5_free_principal (k5, enroll->computer_principal);
		enroll->computer_principal = NULL;
	}

	if (!enroll->computer_password_explicit) {
		free (enroll->computer_password);
		enroll->computer_password = NULL;
	}

	free (enroll->computer_dn);
	enroll->computer_dn = NULL;

	free (enroll->computer_container);
	enroll->computer_container = NULL;

	if (!enroll->service_principals_explicit) {
		_adcli_strv_free (enroll->service_principals);
		enroll->service_principals = NULL;
	}

	if (enroll->user_princpal_generate) {
		free (enroll->user_principal);
		enroll->user_principal = NULL;
	}

	enroll->kvno = 0;

	if (enroll->computer_attributes) {
		ldap_msgfree (enroll->computer_attributes);
		enroll->computer_attributes = NULL;
	}

	if (!enroll->domain_ou_explicit) {
		free (enroll->domain_ou);
		enroll->domain_ou = NULL;
	}
}

adcli_result
adcli_enroll_prepare (adcli_enroll *enroll,
                      adcli_enroll_flags flags)
{
	adcli_result res = ADCLI_SUCCESS;

	return_unexpected_if_fail (enroll != NULL);

	adcli_clear_last_error ();

	if (enroll->is_service) {
		/* Ensure basic params for service accounts */
		res = ensure_host_fqdn (res, enroll);
		res = ensure_computer_name (res, enroll);
		res = ensure_computer_sam (res, enroll);
		res = ensure_computer_password (res, enroll);
		res = ensure_host_keytab (res, enroll);
		res = ensure_keytab_principals (res, enroll);
	} else {
		/* Basic discovery and figuring out enroll params */
		res = ensure_host_fqdn (res, enroll);
		res = ensure_computer_name (res, enroll);
		res = ensure_computer_sam (res, enroll);
		res = ensure_user_principal (res, enroll);
		res = ensure_computer_password (res, enroll);
		if (!(flags & ADCLI_ENROLL_NO_KEYTAB))
			res = ensure_host_keytab (res, enroll);
		res = ensure_service_names (res, enroll);
		res = ensure_service_principals (res, enroll);
		res = ensure_keytab_principals (res, enroll);
	}

	return res;
}

static adcli_result
add_server_side_service_principals (adcli_enroll *enroll)
{
	char **spn_list;
	LDAP *ldap;
	size_t c;
	int length = 0;
	adcli_result res;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	spn_list = _adcli_ldap_parse_values (ldap, enroll->computer_attributes,
	                                     "servicePrincipalName");
	if (spn_list == NULL) {
		return ADCLI_SUCCESS;
	}

	if (enroll->service_principals != NULL) {
		length = seq_count (enroll->service_principals);
	}

	for (c = 0; spn_list[c] != NULL; c++) {
		_adcli_info ("Checking %s", spn_list[c]);
		if (!_adcli_strv_has_ex (enroll->service_principals_to_remove, spn_list[c], strcasecmp)) {
			enroll->service_principals = _adcli_strv_add_unique (enroll->service_principals,
			                                                     strdup (spn_list[c]),
			                                                     &length, false);
			assert (enroll->service_principals != NULL);
			_adcli_info ("   Added %s", spn_list[c]);
		}
	}
	_adcli_strv_free (spn_list);

	res = ensure_keytab_principals (ADCLI_SUCCESS, enroll);
	if (res != ADCLI_SUCCESS) {
		return res;
	}

	return ADCLI_SUCCESS;
}

static adcli_result
enroll_join_or_update_tasks (adcli_enroll *enroll,
		             adcli_enroll_flags flags)
{
	adcli_result res;
	krb5_kvno old_kvno = -1;

	if (!(flags & ADCLI_ENROLL_PASSWORD_VALID)) {

		/* Handle kvno changes for read-only domain controllers
		 * (RODC). Since the actual password change does not happen on
		 * the RODC the kvno change has to be replicated back which
		 * might take some time. So we check the kvno before and after
		 * the change if we are connected to a RODC and increment the
		 * kvno if needed. */
		if (!adcli_conn_is_writeable (enroll->conn)) {
			if (enroll->computer_attributes == NULL) {
				res = retrieve_computer_account (enroll);
				if (res != ADCLI_SUCCESS)
					return res;
			}
			old_kvno = adcli_enroll_get_kvno (enroll);
			_adcli_info ("Found old kvno '%d'", old_kvno);

			ldap_msgfree (enroll->computer_attributes);
			enroll->computer_attributes = NULL;
			adcli_enroll_set_kvno (enroll, 0);
		}

		res = set_computer_password (enroll, flags & ADCLI_ENROLL_LDAP_PASSWD);
		if (res != ADCLI_SUCCESS)
			return res;
	}

	/* kvno is not needed if no keytab */
	if (flags & ADCLI_ENROLL_NO_KEYTAB)
		enroll->kvno = -1;

	/* Get information about the computer account if needed */
	if (enroll->computer_attributes == NULL) {
		res = retrieve_computer_account (enroll);
		if (res != ADCLI_SUCCESS)
			return res;
	}

	/* Handle kvno changes for read-only domain controllers (RODC) */
	if (!adcli_conn_is_writeable (enroll->conn) && old_kvno != -1 &&
	    adcli_enroll_get_kvno (enroll) != 0 &&
	    adcli_enroll_get_kvno (enroll) == old_kvno) {
		enroll->kvno++;
		_adcli_info ("No kvno change detected on read-only DC,  kvno "
		             "will be incremented by 1 to '%d'", enroll->kvno);
	}

	/* We ignore failures of setting these fields */
	update_and_calculate_enctypes (enroll);
	update_computer_account (enroll);

	res = add_server_side_service_principals (enroll);
	if (res != ADCLI_SUCCESS) {
		return res;
	}

	/* service_names is only set from input on the command line, so no
	 * additional check for explicit is needed here */
	if (enroll->service_names != NULL) {
		res = add_service_names_to_service_principals (enroll);
		if (res != ADCLI_SUCCESS) {
			return res;
		}
		res = ensure_keytab_principals (res, enroll);
		if (res != ADCLI_SUCCESS) {
			return res;
		}
	}

	update_service_principals (enroll);

	if ( (flags & ADCLI_ENROLL_ADD_SAMBA_DATA) && ! (flags & ADCLI_ENROLL_PASSWORD_VALID)) {
		res = update_samba_data (enroll);
		if (res != ADCLI_SUCCESS) {
			_adcli_info ("Failed to add Samba specific data, smbd "
			             "or winbindd might not work as "
			             "expected.\n");
		}
	}

	if (flags & ADCLI_ENROLL_NO_KEYTAB)
		return ADCLI_SUCCESS;

	/*
	 * Salting in the keytab is wild, we need to autodetect the format
	 * that we use for salting.
	 */

	return update_keytab_for_principals (enroll, flags);
}

static adcli_result
adcli_enroll_add_description_for_service_account (adcli_enroll *enroll)
{
	const char *fqdn;
	char *desc;

	fqdn = adcli_conn_get_host_fqdn (enroll->conn);
	return_unexpected_if_fail (fqdn != NULL);
	if (asprintf (&desc, "Please do not edit, Service account for %s, "
	                     "managed by adcli.", fqdn) < 0) {
		return_unexpected_if_reached ();
	}

	adcli_enroll_set_description (enroll, desc);
	free (desc);

	return ADCLI_SUCCESS;
}

adcli_result
adcli_enroll_add_keytab_for_service_account (adcli_enroll *enroll)
{
	adcli_result res;
	krb5_context k5;
	krb5_error_code code;
	char def_keytab_name[MAX_KEYTAB_NAME_LEN];
	char *lc_dom_name;
	int ret;

	if (adcli_enroll_get_keytab_name (enroll) == NULL) {
		res = _adcli_krb5_init_context (&k5);
		if (res != ADCLI_SUCCESS) {
			return res;
		}

		code = krb5_kt_default_name (k5, def_keytab_name,
		                             sizeof (def_keytab_name));
		krb5_free_context (k5);
		return_unexpected_if_fail (code == 0);

		lc_dom_name = strdup (adcli_conn_get_domain_name (enroll->conn));
		return_unexpected_if_fail (lc_dom_name != NULL);
		_adcli_str_down (lc_dom_name);


		ret = asprintf (&enroll->keytab_name, "%s.%s", def_keytab_name,
		                                             lc_dom_name);
		free (lc_dom_name);
		return_unexpected_if_fail (ret > 0);
	}

	_adcli_info ("Using service account keytab: %s", enroll->keytab_name);

	return ADCLI_SUCCESS;
}

adcli_result
adcli_enroll_join (adcli_enroll *enroll,
                   adcli_enroll_flags flags)
{
	adcli_result res = ADCLI_SUCCESS;

	return_unexpected_if_fail (enroll != NULL);

	adcli_clear_last_error ();
	enroll_clear_state (enroll);

	res = adcli_conn_discover (enroll->conn);
	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->is_service) {
		res = adcli_enroll_add_description_for_service_account (enroll);
	} else {
		res = ensure_default_service_names (enroll);
	}
	if (res != ADCLI_SUCCESS)
		return res;

	res = adcli_enroll_prepare (enroll, flags);
	if (res != ADCLI_SUCCESS)
		return res;

	/* This is where it really happens */
	res = locate_or_create_computer_account (enroll, flags & ADCLI_ENROLL_ALLOW_OVERWRITE,
	                                         flags & ADCLI_ENROLL_LDAP_PASSWD);
	if (res != ADCLI_SUCCESS)
		return res;

	return enroll_join_or_update_tasks (enroll, flags);
}

adcli_result
adcli_enroll_load (adcli_enroll *enroll)
{
	adcli_result res;

	adcli_clear_last_error ();

	/* Load default info from keytab */
	res = load_host_keytab (enroll);
	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->netbios_computer_name)
		enroll->netbios_computer_name_explicit = 1;
	if (enroll->full_computer_name)
		enroll->full_computer_name_explicit = 1;
	if (enroll->host_fqdn)
		enroll->host_fqdn_explicit = 1;
	if (enroll->service_principals)
		enroll->service_principals_explicit = 1;

	return ADCLI_SUCCESS;
}

adcli_result
adcli_enroll_read_computer_account (adcli_enroll *enroll,
		                    adcli_enroll_flags flags)
{
	adcli_result res = ADCLI_SUCCESS;
	LDAP *ldap;

	return_unexpected_if_fail (enroll != NULL);

	adcli_clear_last_error ();
	enroll_clear_state (enroll);

	res = adcli_conn_discover (enroll->conn);
	if (res != ADCLI_SUCCESS)
		return res;

	res = adcli_enroll_prepare (enroll, flags);
	if (res != ADCLI_SUCCESS)
		return res;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	/* Find the computer dn */
	if (!enroll->computer_dn) {
		res = locate_computer_account (enroll, ldap, false, NULL, NULL);
		if (res != ADCLI_SUCCESS)
			return res;
		if (!enroll->computer_dn) {
			_adcli_err ("No %s account for %s exists",
			            s_or_c (enroll), enroll->computer_sam);
			return ADCLI_ERR_CONFIG;
		}
	}

	/* Get information about the computer account */
	return retrieve_computer_account (enroll);
}

adcli_result
adcli_enroll_update (adcli_enroll *enroll,
		     adcli_enroll_flags flags)
{
	adcli_result res = ADCLI_SUCCESS;
	LDAP *ldap;
	char *value;

	res = adcli_enroll_read_computer_account (enroll, flags);
	if (res != ADCLI_SUCCESS)
		return res;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	value = _adcli_ldap_parse_value (ldap,
	                                 enroll->computer_attributes,
	                                 "pwdLastSet");

	if (_adcli_check_nt_time_string_lifetime (value,
	                adcli_enroll_get_computer_password_lifetime (enroll))) {
		/* Do not update keytab if neither new service principals have
                 * to be added or deleted nor the user principal has to be changed. */
		if (enroll->service_names == NULL
		              && (enroll->user_principal == NULL || enroll->user_princpal_generate)
		              && enroll->service_principals_to_add == NULL
		              && enroll->service_principals_to_remove == NULL) {
			flags |= ADCLI_ENROLL_NO_KEYTAB;
		}
		flags |= ADCLI_ENROLL_PASSWORD_VALID;
	}
	free (value);

	/* We only support password changes for service accounts */
	if (enroll->is_service && (flags & ADCLI_ENROLL_PASSWORD_VALID)) {
		return ADCLI_SUCCESS;
	}

	return enroll_join_or_update_tasks (enroll, flags);
}

adcli_result
adcli_enroll_show_computer_attribute (adcli_enroll *enroll)
{
	LDAP *ldap;
	size_t c;
	char **vals;
	size_t v;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	for (c = 0; default_ad_ldap_attrs[c] != NULL; c++) {
		vals = _adcli_ldap_parse_values (ldap,
		                                 enroll->computer_attributes,
		                                 default_ad_ldap_attrs[c]);
		printf ("%s:\n", default_ad_ldap_attrs[c]);
		if (vals == NULL) {
			printf (" - not set -\n");
		} else {
			for (v = 0; vals[v] != NULL; v++) {
				printf (" %s\n", vals[v]);
			}
		}
		_adcli_strv_free (vals);
	}

	return ADCLI_SUCCESS;
}

adcli_result
adcli_enroll_delete (adcli_enroll *enroll,
                     adcli_enroll_flags delete_flags)
{
	adcli_result res = ADCLI_SUCCESS;
	LDAP *ldap;

	return_unexpected_if_fail (enroll != NULL);

	adcli_clear_last_error ();
	enroll_clear_state (enroll);

	res = adcli_conn_discover (enroll->conn);
	if (res != ADCLI_SUCCESS)
		return res;

	/* Basic discovery and figuring out enroll params */
	res = ensure_host_fqdn (res, enroll);
	res = ensure_computer_name (res, enroll);
	res = ensure_computer_sam (res, enroll);

	if (res != ADCLI_SUCCESS)
		return res;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	/* Find the computer dn */
	if (!enroll->computer_dn) {
		res = locate_computer_account (enroll, ldap, false, NULL, NULL);
		if (res != ADCLI_SUCCESS)
			return res;
		if (!enroll->computer_dn) {
			_adcli_err ("No %s account for %s exists",
			            s_or_c (enroll),
			            enroll->computer_sam);
			return ADCLI_ERR_CONFIG;
		}
	}

	return delete_computer_account (enroll, ldap);
}

adcli_result
adcli_enroll_password (adcli_enroll *enroll)
{
	adcli_result res = ADCLI_SUCCESS;
	LDAP *ldap;

	return_unexpected_if_fail (enroll != NULL);

	adcli_clear_last_error ();
	enroll_clear_state (enroll);

	res = adcli_conn_discover (enroll->conn);
	if (res != ADCLI_SUCCESS)
		return res;

	/* Basic discovery and figuring out enroll params */
	res = ensure_host_fqdn (res, enroll);
	res = ensure_computer_name (res, enroll);
	res = ensure_computer_sam (res, enroll);
	res = ensure_computer_password (res, enroll);

	if (res != ADCLI_SUCCESS)
		return res;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	/* Find the computer dn */
	if (!enroll->computer_dn) {
		res = locate_computer_account (enroll, ldap, false, NULL, NULL);
		if (res != ADCLI_SUCCESS)
			return res;
		if (!enroll->computer_dn) {
			_adcli_err ("No %s account for %s exists",
			            s_or_c (enroll),
			            enroll->computer_sam);
			return ADCLI_ERR_CONFIG;
		}
	}

	return set_computer_password (enroll, 0);
}

adcli_enroll *
adcli_enroll_new (adcli_conn *conn)
{
	adcli_enroll *enroll;
	const char *value;

	return_val_if_fail (conn != NULL, NULL);

	enroll = calloc (1, sizeof (adcli_enroll));
	return_val_if_fail (enroll != NULL, NULL);

	enroll->conn = adcli_conn_ref (conn);
	enroll->refs = 1;

	/* Use the latter sections of host triple as OS name */
	value = strchr (HOST_TRIPLET, '-');
	if (value == NULL)
		value = HOST_TRIPLET;
	else
		value++;
	enroll->os_name = strdup (value);
	return_val_if_fail (enroll->os_name != NULL, NULL);

	enroll->samba_data_tool = strdup (SAMBA_DATA_TOOL);
	return_val_if_fail (enroll->samba_data_tool != NULL, NULL);

	return enroll;
}

adcli_enroll *
adcli_enroll_ref (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	enroll->refs++;
	return enroll;
}

static void
enroll_free (adcli_enroll *enroll)
{
	if (enroll == NULL)
		return;

	enroll_clear_state (enroll);

	free (enroll->computer_sam);
	free (enroll->domain_ou);
	free (enroll->computer_dn);
	free (enroll->keytab_enctypes);

	free (enroll->os_name);
	free (enroll->os_version);
	free (enroll->os_service_pack);
	free (enroll->samba_data_tool);

	free (enroll->user_principal);
	_adcli_strv_free (enroll->service_names);
	_adcli_strv_free (enroll->service_principals);
	_adcli_strv_free (enroll->setattr);
	_adcli_password_free (enroll->computer_password);

	adcli_enroll_set_keytab_name (enroll, NULL);

	adcli_conn_unref (enroll->conn);
	free (enroll);
}

void
adcli_enroll_unref (adcli_enroll *enroll)
{
	if (enroll == NULL)
		return;

	if (--(enroll->refs) > 0)
		return;

	enroll_free (enroll);
}

const char *
adcli_enroll_get_host_fqdn (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->host_fqdn;
}

void
adcli_enroll_set_host_fqdn (adcli_enroll *enroll,
                            const char *value)
{
	return_if_fail (enroll != NULL);
	_adcli_str_set (&enroll->host_fqdn, value);
	enroll->host_fqdn_explicit = 1;
}

const char *
adcli_enroll_get_netbios_computer_name (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->netbios_computer_name;
}

void
adcli_enroll_set_netbios_computer_name (adcli_enroll *enroll,
                                const char *value)
{
	return_if_fail (enroll != NULL);
	_adcli_str_set (&enroll->netbios_computer_name, value);
	enroll->netbios_computer_name_explicit = (value != NULL);
}


const char *
adcli_enroll_get_full_computer_name (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->full_computer_name;
}

void
adcli_enroll_set_full_computer_name (adcli_enroll *enroll,
				const char *value)
{
	return_if_fail (enroll != NULL);
	_adcli_str_set (&enroll->full_computer_name, value);
	enroll->full_computer_name_explicit = (value != NULL);
}

const char *
adcli_enroll_get_domain_ou (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->domain_ou;
}

void
adcli_enroll_set_domain_ou (adcli_enroll *enroll,
                            const char *value)
{
	return_if_fail (enroll != NULL);

	enroll->domain_ou_validated = 0;
	_adcli_str_set (&enroll->domain_ou, value);
	enroll->domain_ou_explicit = (value != NULL);
}

const char *
adcli_enroll_get_computer_dn (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->computer_dn;
}

void
adcli_enroll_set_computer_dn (adcli_enroll *enroll,
                              const char *value)
{
	return_if_fail (enroll != NULL);
	_adcli_str_set (&enroll->computer_dn, value);
}

const char *
adcli_enroll_get_computer_password (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->computer_password;
}

void
adcli_enroll_set_computer_password (adcli_enroll *enroll,
                                    const char *password)
{
	char *newval = NULL;

	return_if_fail (enroll != NULL);

	if (password) {
		newval = strdup (password);
		return_if_fail (newval != NULL);
	}

	if (enroll->computer_password)
		_adcli_password_free (enroll->computer_password);

	enroll->computer_password = newval;
	enroll->computer_password_explicit = (newval != NULL);
}

void
adcli_enroll_reset_computer_password (adcli_enroll *enroll)
{
	return_if_fail (enroll != NULL);

	_adcli_password_free (enroll->computer_password);
	enroll->computer_password = NULL;
	enroll->computer_password_explicit = 0;
	enroll->reset_password = 1;
}

const char **
adcli_enroll_get_service_names (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);

	if (ensure_service_names (ADCLI_SUCCESS, enroll) != ADCLI_SUCCESS)
		return_val_if_reached (NULL);

	return (const char **)enroll->service_names;
}

void
adcli_enroll_set_service_names (adcli_enroll *enroll,
                                const char **value)
{
	return_if_fail (enroll != NULL);
	_adcli_strv_set (&enroll->service_names, value);
}

void
adcli_enroll_add_service_name (adcli_enroll *enroll,
                               const char *value)
{
	return_if_fail (enroll != NULL);
	return_if_fail (value != NULL);

	enroll->service_names = _adcli_strv_add (enroll->service_names, strdup (value), NULL);
	return_if_fail (enroll->service_names != NULL);
}

const char **
adcli_enroll_get_service_principals  (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return (const char **)enroll->service_principals;
}

void
adcli_enroll_set_service_principals (adcli_enroll *enroll,
                                     const char **value)
{
	return_if_fail (enroll != NULL);
	_adcli_strv_set (&enroll->service_principals, value);
	enroll->service_principals_explicit = (value != NULL);
}

krb5_kvno
adcli_enroll_get_kvno (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, 0);
	return enroll->kvno;
}

void
adcli_enroll_set_kvno (adcli_enroll *enroll,
                       krb5_kvno value)
{
	return_if_fail (enroll != NULL);
	enroll->kvno = value;
}

krb5_keytab
adcli_enroll_get_keytab (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->keytab;
}

const char *
adcli_enroll_get_keytab_name (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->keytab_name;
}

void
adcli_enroll_set_keytab_name (adcli_enroll *enroll,
                              const char *value)
{
	char *newval = NULL;
	krb5_context k5;

	return_if_fail (enroll != NULL);

	if (enroll->keytab_name) {
		if (enroll->keytab_name_is_krb5) {
			k5 = adcli_conn_get_krb5_context (enroll->conn);
			return_if_fail (k5 != NULL);
			krb5_free_string (k5, enroll->keytab_name);
		} else {
			free (enroll->keytab_name);
		}
	}

	if (enroll->keytab) {
		k5 = adcli_conn_get_krb5_context (enroll->conn);
		return_if_fail (k5 != NULL);
		krb5_kt_close (k5, enroll->keytab);
		enroll->keytab = NULL;
	}

	if (value) {
		newval = strdup (value);
		return_if_fail (newval != NULL);
	}

	enroll->keytab_name = newval;
	enroll->keytab_name_is_krb5 = 0;
}

#define PROC_SYS_FIPS "/proc/sys/crypto/fips_enabled"

static bool adcli_fips_enabled (void)
{
	int fd;
	ssize_t len;
	char buf[8];

	fd = open (PROC_SYS_FIPS, O_RDONLY);
	if (fd != -1) {
		len = read (fd, buf, sizeof (buf));
		close (fd);
		/* Assume FIPS in enabled if PROC_SYS_FIPS contains a
		 * non-0 value. */
		if ( ! (len == 2 && buf[0] == '0' && buf[1] == '\n')) {
			return true;
		}
	}

	return false;
}

krb5_enctype *
adcli_enroll_get_keytab_enctypes (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	if (enroll->keytab_enctypes)
		return enroll->keytab_enctypes;

	if (adcli_conn_server_has_capability (enroll->conn, ADCLI_CAP_V60_OID))
		if (adcli_fips_enabled ()) {
			return v60_later_enctypes_fips;
		} else {
			return v60_later_enctypes;
		}
	else
		return v51_earlier_enctypes;
}

krb5_enctype *
adcli_enroll_get_permitted_keytab_enctypes (adcli_enroll *enroll)
{
	krb5_enctype *cur_enctypes;
	krb5_enctype *permitted_enctypes;
	krb5_enctype *new_enctypes;
	krb5_error_code code;
	krb5_context k5;
	size_t c;
	size_t p;
	size_t n;

	return_val_if_fail (enroll != NULL, NULL);
	cur_enctypes = adcli_enroll_get_keytab_enctypes (enroll);

	k5 = adcli_conn_get_krb5_context (enroll->conn);
	return_val_if_fail (k5 != NULL, NULL);

	code = krb5_get_permitted_enctypes (k5, &permitted_enctypes);
	return_val_if_fail (code == 0, NULL);

	for (c = 0; cur_enctypes[c] != 0; c++);

	new_enctypes = calloc (c + 1, sizeof (krb5_enctype));
	if (new_enctypes == NULL) {
		krb5_free_enctypes (k5, permitted_enctypes);
		return NULL;
	}

	n = 0;
	for (c = 0; cur_enctypes[c] != 0; c++) {
		for (p = 0; permitted_enctypes[p] != 0; p++) {
			if (cur_enctypes[c] == permitted_enctypes[p]) {
				new_enctypes[n++] = cur_enctypes[c];
				break;
			}
		}
		if (permitted_enctypes[p] == 0) {
			_adcli_info ("Encryption type [%d] not permitted.", cur_enctypes[c]);
		}
	}

	krb5_free_enctypes (k5, permitted_enctypes);

	return new_enctypes;
}

void
adcli_enroll_set_keytab_enctypes (adcli_enroll *enroll,
                                  krb5_enctype *value)
{
	krb5_enctype *newval = NULL;
	int len;

	return_if_fail (enroll != NULL);

	if (value) {
		for (len = 0; value[len] != 0; len++);
		newval = malloc (sizeof (krb5_enctype) * (len + 1));
		return_if_fail (newval != NULL);
		memcpy (newval, value, sizeof (krb5_enctype) * (len + 1));
	}

	free (enroll->keytab_enctypes);
	enroll->keytab_enctypes = newval;
	enroll->keytab_enctypes_explicit = (newval != NULL);
}

const char *
adcli_enroll_get_os_name (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->os_name;
}

void
adcli_enroll_set_os_name (adcli_enroll *enroll,
                          const char *value)
{
	return_if_fail (enroll != NULL);
	if (value && value[0] == '\0')
		value = NULL;
	_adcli_str_set (&enroll->os_name, value);
	enroll->os_name_explicit = 1;
}

const char *
adcli_enroll_get_os_version (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->os_version;
}

void
adcli_enroll_set_os_version (adcli_enroll *enroll,
                             const char *value)
{
	return_if_fail (enroll != NULL);
	if (value && value[0] == '\0')
		value = NULL;
	_adcli_str_set (&enroll->os_version, value);
	enroll->os_version_explicit = 1;
}

const char *
adcli_enroll_get_os_service_pack (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->os_service_pack;
}

void
adcli_enroll_set_os_service_pack (adcli_enroll *enroll,
                                  const char *value)
{
	return_if_fail (enroll != NULL);
	if (value && value[0] == '\0')
		value = NULL;
	_adcli_str_set (&enroll->os_service_pack, value);
	enroll->os_service_pack_explicit = 1;
}

const char *
adcli_enroll_get_user_principal (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->user_principal;
}

void
adcli_enroll_set_user_principal (adcli_enroll *enroll,
                                 const char *value)
{
	return_if_fail (enroll != NULL);
	_adcli_str_set (&enroll->user_principal, value);
	enroll->user_princpal_generate = 0;
}

void
adcli_enroll_auto_user_principal (adcli_enroll *enroll)
{
	return_if_fail (enroll != NULL);
	_adcli_str_set (&enroll->user_principal, NULL);
	enroll->user_princpal_generate = 1;
}

#define DEFAULT_HOST_PW_LIFETIME 30

unsigned int
adcli_enroll_get_computer_password_lifetime (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, DEFAULT_HOST_PW_LIFETIME);
	if (enroll->computer_password_lifetime_explicit) {
		return enroll->computer_password_lifetime;
	}
	return DEFAULT_HOST_PW_LIFETIME;
}

void
adcli_enroll_set_computer_password_lifetime (adcli_enroll *enroll,
                                   unsigned int lifetime)
{
	return_if_fail (enroll != NULL);
	enroll->computer_password_lifetime = lifetime;

	enroll->computer_password_lifetime_explicit = 1;
}

void
adcli_enroll_set_samba_data_tool (adcli_enroll *enroll, const char *value)
{
	return_if_fail (enroll != NULL);
	if (value != NULL && value[0] != '\0') {
		_adcli_str_set (&enroll->samba_data_tool, value);
	}
}

const char *
adcli_enroll_get_samba_data_tool (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->samba_data_tool;
}

bool
adcli_enroll_get_trusted_for_delegation (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, false);

	return enroll->trusted_for_delegation;
}

void
adcli_enroll_set_trusted_for_delegation (adcli_enroll *enroll,
                                         bool value)
{
	return_if_fail (enroll != NULL);

	enroll->trusted_for_delegation = value;
	enroll->trusted_for_delegation_explicit = 1;
}

bool
adcli_enroll_get_dont_expire_password (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, false);

	return enroll->dont_expire_password;
}

void
adcli_enroll_set_dont_expire_password (adcli_enroll *enroll,
                                       bool value)
{
	return_if_fail (enroll != NULL);

	enroll->dont_expire_password = value;
	enroll->dont_expire_password_explicit = 1;
}

bool
adcli_enroll_get_account_disable (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, false);

	return enroll->account_disable;
}

void
adcli_enroll_set_account_disable (adcli_enroll *enroll,
                                  bool value)
{
	return_if_fail (enroll != NULL);

	enroll->account_disable = value;
	enroll->account_disable_explicit = 1;
}

void
adcli_enroll_set_description (adcli_enroll *enroll, const char *value)
{
	return_if_fail (enroll != NULL);
	if (value != NULL && value[0] != '\0') {
		_adcli_str_set (&enroll->description, value);
	}
}

const char *
adcli_enroll_get_desciption (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->description;
}

void
adcli_enroll_set_is_service (adcli_enroll *enroll, bool value)
{
	return_if_fail (enroll != NULL);

	enroll->is_service = value;
	enroll->is_service_explicit = true;
}

bool
adcli_enroll_get_is_service (adcli_enroll *enroll)
{
	return enroll->is_service;
}

const char **
adcli_enroll_get_service_principals_to_add (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);

	return (const char **)enroll->service_principals_to_add;
}

void
adcli_enroll_add_service_principal_to_add (adcli_enroll *enroll,
                                           const char *value)
{
	return_if_fail (enroll != NULL);
	return_if_fail (value != NULL);

	enroll->service_principals_to_add = _adcli_strv_add (enroll->service_principals_to_add,
							    strdup (value), NULL);
	return_if_fail (enroll->service_principals_to_add != NULL);
}

const char **
adcli_enroll_get_service_principals_to_remove (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);

	return (const char **)enroll->service_principals_to_remove;
}

void
adcli_enroll_add_service_principal_to_remove (adcli_enroll *enroll,
                                              const char *value)
{
	return_if_fail (enroll != NULL);
	return_if_fail (value != NULL);

	enroll->service_principals_to_remove = _adcli_strv_add (enroll->service_principals_to_remove,
							    strdup (value), NULL);
	return_if_fail (enroll->service_principals_to_remove != NULL);
}

static int comp_attr_name (const char *s1, const char *s2)
{
	size_t c = 0;

	/* empty strings cannot contain an attribute name */
	if (s1 == NULL || s2 == NULL || *s1 == '\0' || *s2 == '\0') {
		return 1;
	}

	for (c = 0 ; s1[c] != '\0' && s2[c] != '\0'; c++) {
		if (s1[c] == '=' && s2[c] == '=') {
			return 0;
		} else if (tolower (s1[c]) != tolower (s2[c])) {
			return 1;
		}
	}

	return 1;
}

adcli_result
adcli_enroll_add_setattr (adcli_enroll *enroll, const char *value)
{
	char *delim;

	return_val_if_fail (enroll != NULL, ADCLI_ERR_CONFIG);
	return_val_if_fail (value != NULL, ADCLI_ERR_CONFIG);

	delim = strchr (value, '=');
	if (delim == NULL) {
		_adcli_err ("Missing '=' in setattr option [%s]", value);
		return ADCLI_ERR_CONFIG;
	}

	if (*(delim + 1) == '\0') {
		_adcli_err ("Missing value in setattr option [%s]", value);
		return ADCLI_ERR_CONFIG;
	}

	*delim = '\0';
	if (_adcli_strv_has_ex (default_ad_ldap_attrs, value, strcasecmp) == 1) {
		_adcli_err ("Attribute [%s] cannot be set with setattr", value);
		return ADCLI_ERR_CONFIG;
	}
	*delim = '=';

	if (_adcli_strv_has_ex (enroll->setattr, value, comp_attr_name) == 1) {
		_adcli_err ("Attribute [%s] already set", value);
		return ADCLI_ERR_CONFIG;
	}

	enroll->setattr = _adcli_strv_add (enroll->setattr, strdup (value),
	                                   NULL);
	return_val_if_fail (enroll->setattr != NULL, ADCLI_ERR_CONFIG);

	return ADCLI_SUCCESS;
}

const char **
adcli_enroll_get_setattr (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return (const char **) enroll->setattr;
}

adcli_result
adcli_enroll_add_delattr (adcli_enroll *enroll, const char *value)
{
	return_val_if_fail (enroll != NULL, ADCLI_ERR_CONFIG);
	return_val_if_fail (value != NULL, ADCLI_ERR_CONFIG);

	if (_adcli_strv_has_ex (default_ad_ldap_attrs, value, strcasecmp) == 1) {
		_adcli_err ("Attribute [%s] cannot be removed with delattr", value);
		return ADCLI_ERR_CONFIG;
	}

	enroll->delattr = _adcli_strv_add (enroll->delattr, strdup (value),
	                                   NULL);
	return_val_if_fail (enroll->delattr != NULL, ADCLI_ERR_CONFIG);

	return ADCLI_SUCCESS;
}

const char **
adcli_enroll_get_delattr (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return (const char **) enroll->delattr;
}

#ifdef ADENROLL_TESTS

#include "test.h"

static void
test_adcli_enroll_get_permitted_keytab_enctypes (void)
{
	krb5_enctype *enctypes;
	krb5_error_code code;
	krb5_enctype *permitted_enctypes;
	krb5_enctype check_enctypes[3] = { 0 };
	adcli_conn *conn;
	adcli_enroll *enroll;
	adcli_result res;
	krb5_context k5;
	size_t c;

	conn = adcli_conn_new ("test.dom");
	assert_ptr_not_null (conn);

	enroll = adcli_enroll_new (conn);
	assert_ptr_not_null (enroll);

	enctypes = adcli_enroll_get_permitted_keytab_enctypes (NULL);
	assert_ptr_eq (enctypes, NULL);

	/* krb5 context missing */
	enctypes = adcli_enroll_get_permitted_keytab_enctypes (enroll);
	assert_ptr_eq (enctypes, NULL);

	/* check that all permitted enctypes can pass */
	res = _adcli_krb5_init_context (&k5);
	assert_num_eq (res, ADCLI_SUCCESS);

	adcli_conn_set_krb5_context (conn, k5);

	code = krb5_get_permitted_enctypes (k5, &permitted_enctypes);
	assert_num_eq (code, 0);
	assert_ptr_not_null (permitted_enctypes);
	assert_num_cmp (permitted_enctypes[0], !=, 0);

	adcli_enroll_set_keytab_enctypes (enroll, permitted_enctypes);

	enctypes = adcli_enroll_get_permitted_keytab_enctypes (enroll);
	assert_ptr_not_null (enctypes);
	for (c = 0; permitted_enctypes[c] != 0; c++) {
		assert_num_eq (enctypes[c], permitted_enctypes[c]);
	}
	assert_num_eq (enctypes[c], 0);
	krb5_free_enctypes (k5, enctypes);

	/* check that ENCTYPE_UNKNOWN is filtered out */
	check_enctypes[0] = permitted_enctypes[0];
	check_enctypes[1] = ENCTYPE_UNKNOWN;
	check_enctypes[2] = 0;
	adcli_enroll_set_keytab_enctypes (enroll, check_enctypes);

	enctypes = adcli_enroll_get_permitted_keytab_enctypes (enroll);
	assert_ptr_not_null (enctypes);
	assert_num_eq (enctypes[0], permitted_enctypes[0]);
	assert_num_eq (enctypes[1], 0);
	krb5_free_enctypes (k5, enctypes);

	krb5_free_enctypes (k5, permitted_enctypes);

	adcli_enroll_unref (enroll);
	adcli_conn_unref (conn);
}

static void
test_comp_attr_name (void)
{
	assert_num_eq (1, comp_attr_name (NULL ,NULL));
	assert_num_eq (1, comp_attr_name ("" ,NULL));
	assert_num_eq (1, comp_attr_name ("" ,""));
	assert_num_eq (1, comp_attr_name (NULL ,""));
	assert_num_eq (1, comp_attr_name (NULL ,"abc=xyz"));
	assert_num_eq (1, comp_attr_name ("" ,"abc=xyz"));
	assert_num_eq (1, comp_attr_name ("abc=xyz", NULL));
	assert_num_eq (1, comp_attr_name ("abc=xyz", ""));
	assert_num_eq (1, comp_attr_name ("abc=xyz", "ab=xyz"));
	assert_num_eq (1, comp_attr_name ("ab=xyz", "abc=xyz"));
	assert_num_eq (1, comp_attr_name ("abcxyz", "abc=xyz"));
	assert_num_eq (1, comp_attr_name ("abc=xyz", "abcxyz"));
	assert_num_eq (1, comp_attr_name ("abc=xyz", "a"));
	assert_num_eq (1, comp_attr_name ("a", "abc=xyz"));

	assert_num_eq (0, comp_attr_name ("abc=xyz", "abc=xyz"));
	assert_num_eq (0, comp_attr_name ("abc=xyz", "abc=123"));
}

int
main (int argc,
      char *argv[])
{
	test_func (test_adcli_enroll_get_permitted_keytab_enctypes,
	           "/attrs/adcli_enroll_get_permitted_keytab_enctypes");
	test_func (test_comp_attr_name, "/attrs/comp_attr_name");
	return test_run (argc, argv);
}

#endif /* ADENROLL_TESTS */
