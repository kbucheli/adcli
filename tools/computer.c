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
#include "tools.h"

#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

static void
dump_details (adcli_conn *conn,
              adcli_enroll *enroll,
              int show_password)
{
	const char *value;

	printf ("[domain]\n");
	printf ("domain-name = %s\n", adcli_conn_get_domain_name (conn));
	printf ("domain-realm = %s\n", adcli_conn_get_domain_realm (conn));
	printf ("domain-controller = %s\n", adcli_conn_get_domain_controller (conn));
	printf ("domain-short = %s\n", adcli_conn_get_domain_short (conn));
	printf ("domain-SID = %s\n", adcli_conn_get_domain_sid (conn));
	printf ("naming-context = %s\n", adcli_conn_get_default_naming_context (conn));
	printf ("domain-ou = %s\n", adcli_enroll_get_domain_ou (enroll));

	printf ("[computer]\n");
	printf ("host-fqdn = %s\n", adcli_conn_get_host_fqdn (conn));
	printf ("netbios_computer-name = %s\n", adcli_conn_get_netbios_computer_name (conn));
	printf ("full_computer-name = %s\n", adcli_conn_get_full_computer_name (conn));
	printf ("computer-dn = %s\n", adcli_enroll_get_computer_dn (enroll));
	if (show_password)
		printf ("computer-password = %s\n", adcli_enroll_get_computer_password (enroll));

	value = adcli_enroll_get_os_name (enroll);
	if (value)
		printf ("os-name = %s\n", value);

	value = adcli_enroll_get_os_version (enroll);
	if (value)
		printf ("os-version = %s\n", value);

	value = adcli_enroll_get_os_service_pack (enroll);
	if (value)
		printf ("os-service-pack = %s\n", value);

	printf ("[keytab]\n");
	printf ("kvno = %d\n", adcli_enroll_get_kvno (enroll));
	printf ("keytab = %s\n", adcli_enroll_get_keytab_name (enroll));
}

static void
dump_password (adcli_conn *conn,
               adcli_enroll *enroll)
{
	printf ("[computer]\n");
	printf ("computer-password = %s\n", adcli_enroll_get_computer_password (enroll));
}

typedef enum {
	/* Have short equivalents */
	opt_domain = 'D',
	opt_domain_realm = 'R',
	opt_domain_controller = 'S',
	opt_domain_ou = 'O',
	opt_host_fqdn = 'H',
	opt_computer_name = 'N',
	opt_host_keytab = 'K',
	opt_login_user = 'U',
	opt_login_ccache = 'C',
	opt_service_name = 'V',
	opt_prompt_password = 'W',
	opt_verbose = 'v',

	/* Don't have short equivalents */
	opt_login_type = 1000,
	opt_no_password,
	opt_stdin_password,
	opt_one_time_password,
	opt_show_details,
	opt_show_password,
	opt_os_name,
	opt_os_version,
	opt_os_service_pack,
	opt_user_principal,
	opt_computer_password_lifetime,
	opt_add_samba_data,
	opt_samba_data_tool,
	opt_trusted_for_delegation,
	opt_dont_expire_password,
	opt_add_service_principal,
	opt_remove_service_principal,
	opt_description,
	opt_setattr,
	opt_delattr,
	opt_use_ldaps,
	opt_account_disable,
	opt_ldap_passwd,
} Option;

static adcli_tool_desc common_usages[] = {
	{ opt_domain, "active directory domain name" },
	{ opt_domain_realm, "kerberos realm for the domain" },
	{ opt_domain_controller, "domain controller to connect to" },
	{ opt_use_ldaps, "use LDAPS port for communication" },
	{ opt_host_fqdn, "override the fully qualified domain name of the\n"
	                 "local machine" },
	{ opt_host_keytab, "filename for the host kerberos keytab" },
	{ opt_computer_name, "override the netbios short name of the local\n"
	                     "machine" },
	{ opt_login_ccache, "kerberos credential cache file which contains\n"
	                    "ticket to used to connect to the domain" },
	{ opt_login_user, "user (usually administrative) login name of\n"
	                  "the account to log into the domain as" },
	{ opt_login_type, "restrict type of login allowed when connecting to \n"
	                  "the domain, either 'computer' or 'user'" },
	{ opt_domain_ou, "a LDAP DN representing an organizational unit in\n"
	                   "which the computer account should be placed." },
	{ opt_service_name, "additional service name for a kerberos\n"
	                     "service principal to be created on the account" },
	{ opt_os_name, "the computer operating system name", },
	{ opt_os_version, "the computer operating system version", },
	{ opt_os_service_pack, "the computer operating system service pack", },
	{ opt_user_principal, "add an authentication principal to the account", },
	{ opt_computer_password_lifetime, "lifetime of the host accounts password in days", },
	{ opt_trusted_for_delegation, "set/unset the TRUSTED_FOR_DELEGATION flag\n"
	                              "in the userAccountControl attribute", },
	{ opt_dont_expire_password, "set/unset the DONT_EXPIRE_PASSWORD flag\n"
	                            "in the userAccountControl attribute", },
	{ opt_account_disable, "set/unset the ACCOUNTDISABLE flag\n"
	                       "in the userAccountControl attribute", },
	{ opt_add_service_principal, "add the given service principal to the account\n" },
	{ opt_remove_service_principal, "remove the given service principal from the account\n" },
	{ opt_description, "add a description to the account\n" },
	{ opt_setattr, "add an attribute with a value\n" },
	{ opt_delattr, "remove an attribute\n" },
	{ opt_no_password, "don't prompt for or read a password" },
	{ opt_prompt_password, "prompt for a password if necessary" },
	{ opt_stdin_password, "read a password from stdin (until EOF) if\n"
	                      "necessary" },
	{ opt_one_time_password, "password to use for the preset computer\n"
	                         "accounts" },
	{ opt_show_details, "show information about joining the domain after\n"
	                     "a successful join" },
	{ opt_show_password, "show computer account password after a\n"
	                     "successful join" },
	{ opt_add_samba_data, "add domain SID and computer account password\n"
	                      "to the Samba specific configuration database" },
	{ opt_samba_data_tool, "Absolute path to the tool used for add-samba-data" },
	{ opt_ldap_passwd, "Use LDAP add/mod operation to set/change password" },
	{ opt_verbose, "show verbose progress and failure messages", },
	{ 0 },
};

static int
parse_option (Option opt,
              const char *optarg,
              adcli_conn *conn,
              adcli_enroll *enroll)
{
	static int no_password = 0;
	static int prompt_password = 0;
	static int stdin_password = 0;
	char *endptr;
	unsigned int lifetime;
	int ret;

	switch (opt) {
	case opt_login_ccache:
		adcli_conn_set_login_ccache_name (conn, optarg ? optarg : "");
		return ADCLI_SUCCESS;
	case opt_login_user:
		if (adcli_conn_get_allowed_login_types (conn) & ADCLI_LOGIN_USER_ACCOUNT) {
			adcli_conn_set_login_user (conn, optarg);
			adcli_conn_set_allowed_login_types (conn, ADCLI_LOGIN_USER_ACCOUNT);
		} else {
			warnx ("cannot set --user if --login-type not set to 'user'");
			return EUSAGE;
		}
		return ADCLI_SUCCESS;
	case opt_login_type:
		if (optarg && strcmp (optarg, "computer") == 0) {
			if (adcli_conn_get_login_user (conn) != NULL) {
				warnx ("cannot set --login-type to 'computer' if --user is set");
				return EUSAGE;
			} else
				adcli_conn_set_allowed_login_types (conn, ADCLI_LOGIN_COMPUTER_ACCOUNT);
		} else if (optarg && strcmp (optarg, "user") == 0) {
			adcli_conn_set_allowed_login_types (conn, ADCLI_LOGIN_USER_ACCOUNT);

		} else {
			warnx ("unknown login type '%s'", optarg);
			return EUSAGE;
		}
		return ADCLI_SUCCESS;
	case opt_host_fqdn:
		adcli_conn_set_host_fqdn (conn, optarg);
		return ADCLI_SUCCESS;
	case opt_host_keytab:
		adcli_enroll_set_keytab_name (enroll, optarg);
		return ADCLI_SUCCESS;
	case opt_computer_name:
		adcli_conn_set_full_computer_name (conn, optarg);
		adcli_enroll_set_full_computer_name (enroll, optarg);
		return ADCLI_SUCCESS;
	case opt_domain:
		adcli_conn_set_domain_name (conn, optarg);
		return ADCLI_SUCCESS;
	case opt_domain_realm:
		adcli_conn_set_domain_realm (conn, optarg);
		return ADCLI_SUCCESS;
	case opt_domain_controller:
		adcli_conn_set_domain_controller (conn, optarg);
		return ADCLI_SUCCESS;
	case opt_domain_ou:
		adcli_enroll_set_domain_ou (enroll, optarg);
		return ADCLI_SUCCESS;
	case opt_service_name:
		adcli_enroll_add_service_name (enroll, optarg);
		return ADCLI_SUCCESS;
	case opt_no_password:
		if (stdin_password || prompt_password) {
			warnx ("cannot use --no-password argument with %s",
			       stdin_password ? "--stdin-password" : "--prompt-password");
			return EUSAGE;
		} else {
			adcli_conn_set_password_func (conn, NULL, NULL, NULL);
			no_password = 1;
		}
		return ADCLI_SUCCESS;
	case opt_prompt_password:
		if (stdin_password || no_password) {
			warnx ("cannot use --prompt-password argument with %s",
			       stdin_password ? "--stdin-password" : "--no-password");
			return EUSAGE;
		} else {
			adcli_conn_set_password_func (conn, adcli_prompt_password_func, NULL, NULL);
			prompt_password = 1;
		}
		return ADCLI_SUCCESS;
	case opt_stdin_password:
		if (prompt_password || no_password) {
			warnx ("cannot use --stdin-password argument with %s",
			       prompt_password ? "--prompt-password" : "--no-password");
			return EUSAGE;
		} else {
			adcli_conn_set_password_func (conn, adcli_read_password_func, NULL, NULL);
			stdin_password = 1;
		}
		return ADCLI_SUCCESS;
	case opt_os_name:
		adcli_enroll_set_os_name (enroll, optarg);
		return ADCLI_SUCCESS;
	case opt_os_version:
		adcli_enroll_set_os_version (enroll, optarg);
		return ADCLI_SUCCESS;
	case opt_os_service_pack:
		adcli_enroll_set_os_service_pack (enroll, optarg);
		return ADCLI_SUCCESS;
	case opt_user_principal:
		if (optarg && optarg[0])
			adcli_enroll_set_user_principal (enroll, optarg);
		else
			adcli_enroll_auto_user_principal (enroll);
		return ADCLI_SUCCESS;
	case opt_computer_password_lifetime:
		errno = 0;
		lifetime = strtoul (optarg, &endptr, 10);
		if (errno != 0 || *endptr != '\0' || endptr == optarg) {
			warnx ("failure to parse value '%s' of option 'computer-password-lifetime'; "
			       "expecting non-negative integer indicating the lifetime in days",
			       optarg);
			return EUSAGE;
		}

		adcli_enroll_set_computer_password_lifetime (enroll, lifetime);
		return ADCLI_SUCCESS;
	case opt_samba_data_tool:
		errno = 0;
		ret = access (optarg, X_OK);
		if (ret != 0) {
			ret = errno;
			warnx ("Failed to access tool to add Samba data: %s", strerror (ret));
			return EUSAGE;
		} else {
			adcli_enroll_set_samba_data_tool (enroll, optarg);
		}
		return ADCLI_SUCCESS;
	case opt_trusted_for_delegation:
		if (strcasecmp (optarg, "true") == 0 || strcasecmp (optarg, "yes") == 0) {
			adcli_enroll_set_trusted_for_delegation (enroll, true);
		} else {
			adcli_enroll_set_trusted_for_delegation (enroll, false);
		}
		return ADCLI_SUCCESS;
	case opt_dont_expire_password:
		if (strcasecmp (optarg, "true") == 0 || strcasecmp (optarg, "yes") == 0) {
			adcli_enroll_set_dont_expire_password (enroll, true);
		} else {
			adcli_enroll_set_dont_expire_password (enroll, false);
		}
		return ADCLI_SUCCESS;
	case opt_account_disable:
		if (strcasecmp (optarg, "true") == 0 || strcasecmp (optarg, "yes") == 0) {
			adcli_enroll_set_account_disable (enroll, true);
		} else {
			adcli_enroll_set_account_disable (enroll, false);
		}
		return ADCLI_SUCCESS;
	case opt_add_service_principal:
		adcli_enroll_add_service_principal_to_add (enroll, optarg);
		return ADCLI_SUCCESS;
	case opt_remove_service_principal:
		adcli_enroll_add_service_principal_to_remove (enroll, optarg);
		return ADCLI_SUCCESS;
	case opt_description:
		adcli_enroll_set_description (enroll, optarg);
		return ADCLI_SUCCESS;
	case opt_setattr:
		ret =  adcli_enroll_add_setattr (enroll, optarg);
		if (ret != ADCLI_SUCCESS) {
			warnx ("parsing setattr option failed");
		}
		return ret;
	case opt_delattr:
		ret = adcli_enroll_add_delattr (enroll, optarg);
		if (ret != ADCLI_SUCCESS) {
			warnx ("parsing delattr option failed");
		}
		return ret;
	case opt_use_ldaps:
		adcli_conn_set_use_ldaps (conn, true);
		return ADCLI_SUCCESS;
	case opt_verbose:
		return ADCLI_SUCCESS;

	/* Should be handled by caller */
	case opt_show_details:
	case opt_show_password:
	case opt_one_time_password:
	case opt_add_samba_data:
	case opt_ldap_passwd:
		assert (0 && "not reached");
		break;
	}

	warnx ("failure to parse option '%c'", opt);
	return EUSAGE;
}

static void
parse_fqdn_or_name (adcli_enroll *enroll,
                    const char *arg)
{
	adcli_enroll_set_netbios_computer_name (enroll, NULL);
	if (strchr (arg, '.') != NULL) {
		adcli_enroll_set_host_fqdn (enroll, arg);
		adcli_enroll_set_full_computer_name (enroll, NULL);
	} else {
		adcli_enroll_set_full_computer_name (enroll, arg);
		adcli_enroll_set_host_fqdn (enroll, NULL);
	}
}

int
adcli_tool_computer_join (adcli_conn *conn,
                          int argc,
                          char *argv[])
{
	adcli_enroll_flags flags = ADCLI_ENROLL_ALLOW_OVERWRITE;
	adcli_enroll *enroll;
	adcli_result res;
	int show_password = 0;
	int details = 0;
	int opt;

	struct option options[] = {
		{ "domain", required_argument, NULL, opt_domain },
		{ "domain-realm", required_argument, NULL, opt_domain_realm },
		{ "domain-controller", required_argument, NULL, opt_domain_controller },
		{ "domain-server", required_argument, NULL, opt_domain_controller }, /* compat */
		{ "use-ldaps", no_argument, 0, opt_use_ldaps },
		{ "login-user", required_argument, NULL, opt_login_user },
		{ "user", required_argument, NULL, opt_login_user }, /* compat */
		{ "login-ccache", optional_argument, NULL, opt_login_ccache },
		{ "login-type", required_argument, NULL, opt_login_type },
		{ "host-fqdn", required_argument, 0, opt_host_fqdn },
		{ "computer-name", required_argument, 0, opt_computer_name },
		{ "host-keytab", required_argument, 0, opt_host_keytab },
		{ "no-password", no_argument, 0, opt_no_password },
		{ "stdin-password", no_argument, 0, opt_stdin_password },
		{ "prompt-password", no_argument, 0, opt_prompt_password },
		{ "one-time-password", required_argument, 0, opt_one_time_password },
		{ "domain-ou", required_argument, NULL, opt_domain_ou },
		{ "computer-ou", required_argument, NULL, opt_domain_ou }, /* compat */
		{ "service-name", required_argument, NULL, opt_service_name },
		{ "os-name", required_argument, NULL, opt_os_name },
		{ "os-version", required_argument, NULL, opt_os_version },
		{ "os-service-pack", optional_argument, NULL, opt_os_service_pack },
		{ "description", optional_argument, NULL, opt_description },
		{ "setattr", required_argument, NULL, opt_setattr },
		{ "user-principal", optional_argument, NULL, opt_user_principal },
		{ "trusted-for-delegation", required_argument, NULL, opt_trusted_for_delegation },
		{ "dont-expire-password", required_argument, NULL, opt_dont_expire_password },
		{ "add-service-principal", required_argument, NULL, opt_add_service_principal },
		{ "show-details", no_argument, NULL, opt_show_details },
		{ "show-password", no_argument, NULL, opt_show_password },
		{ "add-samba-data", no_argument, NULL, opt_add_samba_data },
		{ "samba-data-tool", required_argument, 0, opt_samba_data_tool },
		{ "ldap-passwd", no_argument, NULL, opt_ldap_passwd },
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "help", no_argument, NULL, 'h' },
		{ 0 },
	};

	static adcli_tool_desc usages[] = {
		{ 0, "usage: adcli join --domain=xxxx" },
		{ 0 },
	};

	enroll = adcli_enroll_new (conn);
	if (enroll == NULL) {
		warnx ("unexpected memory problems");
		return -1;
	}

	while ((opt = adcli_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_one_time_password:
			adcli_conn_set_allowed_login_types (conn, ADCLI_LOGIN_COMPUTER_ACCOUNT);
			adcli_conn_set_computer_password (conn, optarg);
			break;
		case opt_show_details:
			details = 1;
			break;
		case opt_show_password:
			show_password = 1;
			break;
		case opt_add_samba_data:
			flags |= ADCLI_ENROLL_ADD_SAMBA_DATA;
			break;
		case opt_ldap_passwd:
			flags |= ADCLI_ENROLL_LDAP_PASSWD;
			break;
		case 'h':
		case '?':
		case ':':
			adcli_tool_usage (options, usages);
			adcli_tool_usage (options, common_usages);
			adcli_enroll_unref (enroll);
			return opt == 'h' ? 0 : 2;
		default:
			res = parse_option ((Option)opt, optarg, conn, enroll);
			if (res != ADCLI_SUCCESS) {
				adcli_enroll_unref (enroll);
				return res;
			}
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 1)
		adcli_conn_set_domain_name (conn, argv[0]);
	else if (argc > 1) {
		warnx ("extra arguments specified");
		adcli_enroll_unref (enroll);
		return 2;
	}

	res = adcli_conn_connect (conn);
	if (res != ADCLI_SUCCESS) {
		warnx ("couldn't connect to %s domain: %s",
		       adcli_conn_get_domain_name (conn),
		       adcli_get_last_error ());
		adcli_enroll_unref (enroll);
		return -res;
	}

	/* Make sure account is enabled after the join */
	adcli_enroll_set_account_disable (enroll, false);
	res = adcli_enroll_join (enroll, flags);
	if (res != ADCLI_SUCCESS) {
		warnx ("joining domain %s failed: %s",
		       adcli_conn_get_domain_name (conn),
		       adcli_get_last_error ());
		adcli_enroll_unref (enroll);
		return -res;
	}

	if (details)
		dump_details (conn, enroll, show_password);
	else if (show_password)
		dump_password (conn, enroll);

	adcli_enroll_unref (enroll);

	return 0;
}

int
adcli_tool_computer_update (adcli_conn *conn,
		            int argc,
                            char *argv[])
{
	adcli_enroll_flags flags = ADCLI_ENROLL_ALLOW_OVERWRITE;
	adcli_enroll *enroll;
	adcli_result res;
	int show_password = 0;
	int details = 0;
	const char *ktname;
	int opt;

	struct option options[] = {
		{ "domain", required_argument, NULL, opt_domain },
		{ "domain-controller", required_argument, NULL, opt_domain_controller },
		{ "use-ldaps", no_argument, 0, opt_use_ldaps },
		{ "host-fqdn", required_argument, 0, opt_host_fqdn },
		{ "computer-name", required_argument, 0, opt_computer_name },
		{ "host-keytab", required_argument, 0, opt_host_keytab },
		{ "login-ccache", optional_argument, NULL, opt_login_ccache },
		{ "service-name", required_argument, NULL, opt_service_name },
		{ "os-name", required_argument, NULL, opt_os_name },
		{ "os-version", required_argument, NULL, opt_os_version },
		{ "os-service-pack", optional_argument, NULL, opt_os_service_pack },
		{ "description", optional_argument, NULL, opt_description },
		{ "setattr", required_argument, NULL, opt_setattr },
		{ "delattr", required_argument, NULL, opt_delattr },
		{ "user-principal", optional_argument, NULL, opt_user_principal },
		{ "computer-password-lifetime", optional_argument, NULL, opt_computer_password_lifetime },
		{ "trusted-for-delegation", required_argument, NULL, opt_trusted_for_delegation },
		{ "dont-expire-password", required_argument, NULL, opt_dont_expire_password },
		{ "account-disable", required_argument, NULL, opt_account_disable },
		{ "add-service-principal", required_argument, NULL, opt_add_service_principal },
		{ "remove-service-principal", required_argument, NULL, opt_remove_service_principal },
		{ "show-details", no_argument, NULL, opt_show_details },
		{ "show-password", no_argument, NULL, opt_show_password },
		{ "add-samba-data", no_argument, NULL, opt_add_samba_data },
		{ "samba-data-tool", required_argument, 0, opt_samba_data_tool },
		{ "ldap-passwd", no_argument, NULL, opt_ldap_passwd },
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "help", no_argument, NULL, 'h' },
		{ 0 },
	};

	static adcli_tool_desc usages[] = {
		{ 0, "usage: adcli update" },
		{ 0 },
	};

	enroll = adcli_enroll_new (conn);
	if (enroll == NULL) {
		warnx ("unexpected memory problems");
		return -1;
	}

	while ((opt = adcli_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_show_details:
			details = 1;
			break;
		case opt_show_password:
			show_password = 1;
			break;
		case opt_add_samba_data:
			flags |= ADCLI_ENROLL_ADD_SAMBA_DATA;
			break;
		case opt_ldap_passwd:
			flags |= ADCLI_ENROLL_LDAP_PASSWD;
			break;
		case 'h':
		case '?':
		case ':':
			adcli_tool_usage (options, usages);
			adcli_tool_usage (options, common_usages);
			adcli_enroll_unref (enroll);
			return opt == 'h' ? 0 : 2;
		default:
			res = parse_option ((Option)opt, optarg, conn, enroll);
			if (res != ADCLI_SUCCESS) {
				adcli_enroll_unref (enroll);
				return res;
			}
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (adcli_conn_get_login_ccache_name (conn) == NULL) {
		/* Force use of a keytab for computer account login */
		adcli_conn_set_allowed_login_types (conn, ADCLI_LOGIN_COMPUTER_ACCOUNT);
		ktname = adcli_enroll_get_keytab_name (enroll);
		adcli_conn_set_login_keytab_name (conn, ktname ? ktname : "");
	}

	res = adcli_enroll_load (enroll);
	if (res != ADCLI_SUCCESS) {
		warnx ("couldn't lookup domain info from keytab: %s",
		       adcli_get_last_error ());
		adcli_enroll_unref (enroll);
		return -res;
	}

	res = adcli_conn_connect (conn);
	if (res != ADCLI_SUCCESS) {
		warnx ("couldn't connect to %s domain: %s",
		       adcli_conn_get_domain_name (conn),
		       adcli_get_last_error ());
		adcli_enroll_unref (enroll);
		return -res;
	}

	res = adcli_enroll_update (enroll, flags);
	if (res != ADCLI_SUCCESS) {
		warnx ("updating membership with domain %s failed: %s",
		       adcli_conn_get_domain_name (conn),
		       adcli_get_last_error ());
		adcli_enroll_unref (enroll);
		return -res;
	}

	if (details)
		dump_details (conn, enroll, show_password);
	else if (show_password)
		dump_password (conn, enroll);

	adcli_enroll_unref (enroll);

	return 0;
}

int
adcli_tool_computer_testjoin (adcli_conn *conn,
                              int argc,
                              char *argv[])
{
	adcli_enroll *enroll;
	adcli_result res;
	const char *ktname;
	int opt;

	struct option options[] = {
		{ "domain", required_argument, NULL, opt_domain },
		{ "domain-controller", required_argument, NULL, opt_domain_controller },
		{ "use-ldaps", no_argument, 0, opt_use_ldaps },
		{ "host-keytab", required_argument, 0, opt_host_keytab },
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "help", no_argument, NULL, 'h' },
		{ 0 },
	};

	static adcli_tool_desc usages[] = {
		{ 0, "usage: adcli testjoin" },
		{ 0 },
	};

	enroll = adcli_enroll_new (conn);
	if (enroll == NULL) {
		warnx ("unexpected memory problems");
		return -1;
	}

	while ((opt = adcli_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case 'h':
		case '?':
		case ':':
			adcli_tool_usage (options, usages);
			adcli_tool_usage (options, common_usages);
			adcli_enroll_unref (enroll);
			return opt == 'h' ? 0 : 2;
		default:
			res = parse_option ((Option)opt, optarg, conn, enroll);
			if (res != ADCLI_SUCCESS) {
				adcli_enroll_unref (enroll);
				return res;
			}
			break;
		}
	}

	/* Force use of a keytab to test the join/machine account password */
	adcli_conn_set_allowed_login_types (conn, ADCLI_LOGIN_COMPUTER_ACCOUNT);
	ktname = adcli_enroll_get_keytab_name (enroll);
	adcli_conn_set_login_keytab_name (conn, ktname ? ktname : "");

	res = adcli_enroll_load (enroll);
	if (res != ADCLI_SUCCESS) {
		adcli_enroll_unref (enroll);
		warnx ("couldn't lookup domain info from keytab: %s",
		       adcli_get_last_error ());
		return -res;
	}

	res = adcli_conn_connect (conn);
	if (res != ADCLI_SUCCESS) {
		adcli_enroll_unref (enroll);
		warnx ("couldn't connect to %s domain: %s",
		      adcli_conn_get_domain_name (conn),
		      adcli_get_last_error ());
		return -res;
	}

	printf ("Sucessfully validated join to domain %s\n",
	        adcli_conn_get_domain_name (conn));

	adcli_enroll_unref (enroll);

	return 0;
}

int
adcli_tool_computer_preset (adcli_conn *conn,
                            int argc,
                            char *argv[])
{
	adcli_enroll *enroll;
	adcli_result res;
	adcli_enroll_flags flags;
	int reset_password = 1;
	int opt;
	int i;

	struct option options[] = {
		{ "domain", required_argument, NULL, opt_domain },
		{ "domain-realm", required_argument, NULL, opt_domain_realm },
		{ "domain-controller", required_argument, NULL, opt_domain_controller },
		{ "use-ldaps", no_argument, 0, opt_use_ldaps },
		{ "domain-ou", required_argument, NULL, opt_domain_ou },
		{ "login-user", required_argument, NULL, opt_login_user },
		{ "login-ccache", optional_argument, NULL, opt_login_ccache },
		{ "no-password", no_argument, 0, opt_no_password },
		{ "stdin-password", no_argument, 0, opt_stdin_password },
		{ "prompt-password", no_argument, 0, opt_prompt_password },
		{ "one-time-password", required_argument, 0, opt_one_time_password },
		{ "service-name", required_argument, NULL, opt_service_name },
		{ "os-name", optional_argument, NULL, opt_os_name },
		{ "os-version", optional_argument, NULL, opt_os_version },
		{ "os-service-pack", optional_argument, NULL, opt_os_service_pack },
		{ "user-principal", no_argument, NULL, opt_user_principal },
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "help", no_argument, NULL, 'h' },
		{ 0 },
	};

	static adcli_tool_desc usages[] = {
		{ 0, "usage: adcli preset-computer --domain=xxxx host1.example.com ..." },
		{ 0 },
	};

	enroll = adcli_enroll_new (conn);
	if (enroll == NULL) {
		warnx ("unexpected memory problems");
		return -1;
	}
	flags = ADCLI_ENROLL_NO_KEYTAB;

	while ((opt = adcli_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_one_time_password:
			adcli_enroll_set_computer_password (enroll, optarg);
			break;
		case 'h':
			adcli_tool_usage (options, usages);
			adcli_tool_usage (options, common_usages);
			adcli_enroll_unref (enroll);
			return 0;
		case '?':
		case ':':
			adcli_tool_usage (options, usages);
			adcli_tool_usage (options, common_usages);
			adcli_enroll_unref (enroll);
			return 2;
		default:
			res = parse_option ((Option)opt, optarg, conn, enroll);
			if (res != ADCLI_SUCCESS) {
				adcli_enroll_unref (enroll);
				return res;
			}
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		warnx ("specify one or more host names of computer accounts to preset");
		adcli_enroll_unref (enroll);
		return EUSAGE;
	}

	adcli_conn_set_allowed_login_types (conn, ADCLI_LOGIN_USER_ACCOUNT);
	reset_password = (adcli_enroll_get_computer_password (enroll) == NULL);

	res = adcli_conn_connect (conn);
	if (res != ADCLI_SUCCESS) {
		warnx ("couldn't connect to %s domain: %s",
		       adcli_conn_get_domain_name (conn),
		       adcli_get_last_error ());
		adcli_enroll_unref (enroll);
		return -res;
	}

	for (i = 0; i < argc; i++) {
		parse_fqdn_or_name (enroll, argv[i]);

		if (reset_password)
			adcli_enroll_reset_computer_password (enroll);

		res = adcli_enroll_join (enroll, flags);
		if (res != ADCLI_SUCCESS) {
			warnx ("presetting %s in %s domain failed: %s", argv[i],
			       adcli_conn_get_domain_name (conn),
			       adcli_get_last_error ());
			adcli_enroll_unref (enroll);
			return -res;
		}

		printf ("netbios-computer-name: %s\n", adcli_enroll_get_netbios_computer_name (enroll));
	}

	adcli_enroll_unref (enroll);

	return 0;
}

int
adcli_tool_computer_reset (adcli_conn *conn,
                           int argc,
                           char *argv[])
{
	adcli_enroll *enroll;
	adcli_result res;
	int opt;

	struct option options[] = {
		{ "domain", required_argument, NULL, opt_domain },
		{ "domain-realm", required_argument, NULL, opt_domain_realm },
		{ "domain-controller", required_argument, NULL, opt_domain_controller },
		{ "use-ldaps", no_argument, 0, opt_use_ldaps },
		{ "login-user", required_argument, NULL, opt_login_user },
		{ "login-ccache", optional_argument, NULL, opt_login_ccache },
		{ "login-type", required_argument, NULL, opt_login_type },
		{ "no-password", no_argument, 0, opt_no_password },
		{ "stdin-password", no_argument, 0, opt_stdin_password },
		{ "prompt-password", no_argument, 0, opt_prompt_password },
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "help", no_argument, NULL, 'h' },
		{ 0 },
	};

	static adcli_tool_desc usages[] = {
		{ 0, "usage: adcli reset-computer --domain=xxxx host1.example.com" },
		{ 0 },
	};

	enroll = adcli_enroll_new (conn);
	if (enroll == NULL) {
		warnx ("unexpected memory problems");
		return -1;
	}

	while ((opt = adcli_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case 'h':
		case '?':
		case ':':
			adcli_tool_usage (options, usages);
			adcli_tool_usage (options, common_usages);
			adcli_enroll_unref (enroll);
			return opt == 'h' ? 0 : 2;
		default:
			res = parse_option ((Option)opt, optarg, conn, enroll);
			if (res != ADCLI_SUCCESS) {
				adcli_enroll_unref (enroll);
				return res;
			}
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		warnx ("specify one host name of computer account to reset");
		adcli_enroll_unref (enroll);
		return EUSAGE;
	}

	res = adcli_conn_connect (conn);
	if (res != ADCLI_SUCCESS) {
		warnx ("couldn't connect to %s domain: %s",
		       adcli_conn_get_domain_name (conn),
		       adcli_get_last_error ());
		adcli_enroll_unref (enroll);
		return -res;
	}

	parse_fqdn_or_name (enroll, argv[0]);
	adcli_enroll_reset_computer_password (enroll);

	res = adcli_enroll_password (enroll);
	if (res != ADCLI_SUCCESS) {
		warnx ("resetting %s in %s domain failed: %s", argv[0],
		       adcli_conn_get_domain_name (conn),
		       adcli_get_last_error ());
		adcli_enroll_unref (enroll);
		return -res;
	}

	adcli_enroll_unref (enroll);
	return 0;
}

int
adcli_tool_computer_delete (adcli_conn *conn,
                            int argc,
                            char *argv[])
{
	adcli_enroll *enroll;
	adcli_result res;
	int opt;

	struct option options[] = {
		{ "domain", required_argument, NULL, opt_domain },
		{ "domain-realm", required_argument, NULL, opt_domain_realm },
		{ "domain-controller", required_argument, NULL, opt_domain_controller },
		{ "use-ldaps", no_argument, 0, opt_use_ldaps },
		{ "login-user", required_argument, NULL, opt_login_user },
		{ "login-ccache", optional_argument, NULL, opt_login_ccache },
		{ "no-password", no_argument, 0, opt_no_password },
		{ "stdin-password", no_argument, 0, opt_stdin_password },
		{ "prompt-password", no_argument, 0, opt_prompt_password },
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "help", no_argument, NULL, 'h' },
		{ 0 },
	};

	static adcli_tool_desc usages[] = {
		{ 0, "usage: adcli delete-computer --domain=xxxx [host1.example.com]" },
		{ 0 },
	};

	enroll = adcli_enroll_new (conn);
	if (enroll == NULL) {
		warnx ("unexpected memory problems");
		return -1;
	}

	while ((opt = adcli_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case 'h':
		case '?':
		case ':':
			adcli_tool_usage (options, usages);
			adcli_tool_usage (options, common_usages);
			adcli_enroll_unref (enroll);
			return opt == 'h' ? 0 : 2;
		default:
			res = parse_option ((Option)opt, optarg, conn, enroll);
			if (res != ADCLI_SUCCESS) {
				adcli_enroll_unref (enroll);
				return res;
			}
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 1) {
		warnx ("specify one host name of computer account to delete");
		adcli_enroll_unref (enroll);
		return EUSAGE;
	}

	adcli_conn_set_allowed_login_types (conn, ADCLI_LOGIN_USER_ACCOUNT);

	res = adcli_enroll_load (enroll);
	if (res != ADCLI_SUCCESS) {
		warnx ("couldn't lookup domain info from keytab: %s",
		       adcli_get_last_error ());
	}

	res = adcli_conn_connect (conn);
	if (res != ADCLI_SUCCESS) {
		warnx ("couldn't connect to %s domain: %s",
		       adcli_conn_get_domain_name (conn),
		       adcli_get_last_error ());
		adcli_enroll_unref (enroll);
		return -res;
	}

	if (argc == 1)
		parse_fqdn_or_name (enroll, argv[0]);

	res = adcli_enroll_delete (enroll, 0);
	if (res != ADCLI_SUCCESS) {
		warnx ("deleting %s in %s domain failed: %s", argv[0],
		       adcli_conn_get_domain_name (conn),
		       adcli_get_last_error ());
		adcli_enroll_unref (enroll);
		return -res;
	}

	adcli_enroll_unref (enroll);
	return 0;
}

int
adcli_tool_computer_show (adcli_conn *conn,
                          int argc,
                          char *argv[])
{
	adcli_enroll *enroll;
	adcli_result res;
	int opt;

	struct option options[] = {
		{ "domain", required_argument, NULL, opt_domain },
		{ "domain-realm", required_argument, NULL, opt_domain_realm },
		{ "domain-controller", required_argument, NULL, opt_domain_controller },
		{ "use-ldaps", no_argument, 0, opt_use_ldaps },
		{ "login-user", required_argument, NULL, opt_login_user },
		{ "login-ccache", optional_argument, NULL, opt_login_ccache },
		{ "login-type", required_argument, NULL, opt_login_type },
		{ "no-password", no_argument, 0, opt_no_password },
		{ "stdin-password", no_argument, 0, opt_stdin_password },
		{ "prompt-password", no_argument, 0, opt_prompt_password },
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "help", no_argument, NULL, 'h' },
		{ 0 },
	};

	static adcli_tool_desc usages[] = {
		{ 0, "usage: adcli show-computer --domain=xxxx host1.example.com" },
		{ 0 },
	};

	enroll = adcli_enroll_new (conn);
	if (enroll == NULL) {
		warnx ("unexpected memory problems");
		return -1;
	}

	while ((opt = adcli_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case 'h':
		case '?':
		case ':':
			adcli_tool_usage (options, usages);
			adcli_tool_usage (options, common_usages);
			adcli_enroll_unref (enroll);
			return opt == 'h' ? 0 : 2;
		default:
			res = parse_option ((Option)opt, optarg, conn, enroll);
			if (res != ADCLI_SUCCESS) {
				adcli_enroll_unref (enroll);
				return res;
			}
			break;
		}
	}

	argc -= optind;
	argv += optind;

	res = adcli_conn_connect (conn);
	if (res != ADCLI_SUCCESS) {
		warnx ("couldn't connect to %s domain: %s",
		       adcli_conn_get_domain_name (conn),
		       adcli_get_last_error ());
		adcli_enroll_unref (enroll);
		return -res;
	}

	if (argc == 1) {
		parse_fqdn_or_name (enroll, argv[0]);
	}

	res = adcli_enroll_read_computer_account (enroll, 0);
	if (res != ADCLI_SUCCESS) {
		warnx ("couldn't read data for %s: %s",
		       adcli_enroll_get_host_fqdn (enroll) != NULL
		           ? adcli_enroll_get_host_fqdn (enroll)
		           : adcli_enroll_get_netbios_computer_name (enroll),
		       adcli_get_last_error ());
		adcli_enroll_unref (enroll);
		return -res;
	}

	res = adcli_enroll_show_computer_attribute (enroll);
	if (res != ADCLI_SUCCESS) {
		warnx ("couldn't print data for %s: %s",
		       argv[0], adcli_get_last_error ());
		adcli_enroll_unref (enroll);
		return -res;
	}

	adcli_enroll_unref (enroll);
	return 0;
}

int
adcli_tool_computer_managed_service_account (adcli_conn *conn,
                                             int argc,
                                             char *argv[])
{
	adcli_enroll *enroll;
	adcli_result res;
	int show_password = 0;
	int details = 0;
	int opt;

	struct option options[] = {
		{ "domain", required_argument, NULL, opt_domain },
		{ "domain-realm", required_argument, NULL, opt_domain_realm },
		{ "domain-controller", required_argument, NULL, opt_domain_controller },
		{ "use-ldaps", no_argument, 0, opt_use_ldaps },
		{ "login-user", required_argument, NULL, opt_login_user },
		{ "login-ccache", optional_argument, NULL, opt_login_ccache },
		{ "host-fqdn", required_argument, 0, opt_host_fqdn },
		{ "computer-name", required_argument, 0, opt_computer_name },
		{ "host-keytab", required_argument, 0, opt_host_keytab },
		{ "no-password", no_argument, 0, opt_no_password },
		{ "stdin-password", no_argument, 0, opt_stdin_password },
		{ "prompt-password", no_argument, 0, opt_prompt_password },
		{ "domain-ou", required_argument, NULL, opt_domain_ou },
		{ "show-details", no_argument, NULL, opt_show_details },
		{ "show-password", no_argument, NULL, opt_show_password },
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "help", no_argument, NULL, 'h' },
		{ 0 },
	};

	static adcli_tool_desc usages[] = {
		{ 0, "usage: adcli create-msa --domain=xxxx" },
		{ 0 },
	};

	enroll = adcli_enroll_new (conn);
	if (enroll == NULL) {
		warnx ("unexpected memory problems");
		return -1;
	}

	while ((opt = adcli_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_one_time_password:
			adcli_conn_set_allowed_login_types (conn, ADCLI_LOGIN_COMPUTER_ACCOUNT);
			adcli_conn_set_computer_password (conn, optarg);
			break;
		case opt_show_details:
			details = 1;
			break;
		case opt_show_password:
			show_password = 1;
			break;
		case 'h':
		case '?':
		case ':':
			adcli_tool_usage (options, usages);
			adcli_tool_usage (options, common_usages);
			adcli_enroll_unref (enroll);
			return opt == 'h' ? 0 : 2;
		default:
			res = parse_option ((Option)opt, optarg, conn, enroll);
			if (res != ADCLI_SUCCESS) {
				adcli_enroll_unref (enroll);
				return res;
			}
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 1)
		adcli_conn_set_domain_name (conn, argv[0]);
	else if (argc > 1) {
		warnx ("extra arguments specified");
		adcli_enroll_unref (enroll);
		return 2;
	}

	if (adcli_conn_get_domain_name (conn) == NULL) {
		warnx ("domain name is required");
		adcli_enroll_unref (enroll);
		return 2;
	}

	adcli_enroll_set_is_service (enroll, true);
	adcli_conn_set_allowed_login_types (conn, ADCLI_LOGIN_USER_ACCOUNT);
	res = adcli_enroll_add_keytab_for_service_account (enroll);
	if (res != ADCLI_SUCCESS) {
		warnx ("Failed to set domain specific keytab name");
		adcli_enroll_unref (enroll);
		return 2;
	}

	res = adcli_enroll_load (enroll);
	if (res != ADCLI_SUCCESS) {
		/* ignored */
	}

	res = adcli_conn_connect (conn);
	if (res != ADCLI_SUCCESS) {
		warnx ("couldn't connect to %s domain: %s",
		       adcli_conn_get_domain_name (conn),
		       adcli_get_last_error ());
		adcli_enroll_unref (enroll);
		return -res;
	}

	res = adcli_enroll_join (enroll, 0);
	if (res != ADCLI_SUCCESS) {
		warnx ("Adding service account for %s failed: %s",
		       adcli_conn_get_domain_name (conn),
		       adcli_get_last_error ());
		adcli_enroll_unref (enroll);
		return -res;
	}

	if (details)
		dump_details (conn, enroll, show_password);
	else if (show_password)
		dump_password (conn, enroll);

	adcli_enroll_unref (enroll);

	return 0;
}
