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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"

#include "adenroll.h"
#include "adprivate.h"

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

struct _adcli_enroll {
	int refs;
	adcli_conn *conn;

	char *host_fqdn;
	int host_fqdn_explicit;
	char *computer_name;
	int computer_name_explicit;
	char *computer_sam;
	char *computer_password;
	int computer_password_explicit;
	int reset_password;
	krb5_principal computer_principal;

	char *preferred_ou;
	int preferred_ou_validated;
	char *computer_container;
	char *computer_dn;
	LDAPMessage *computer_attributes;

	char **service_names;
	char **service_principals;
	int service_principals_explicit;

	krb5_kvno kvno;
	char *keytab_name;
	int keytab_name_is_krb5;
	krb5_keytab keytab;
	krb5_principal *keytab_principals;
	krb5_enctype *keytab_enctypes;
	int keytab_enctypes_explicit;
};

static adcli_result
ensure_host_fqdn (adcli_result res,
                  adcli_enroll *enroll)
{
	const char *fqdn;

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->host_fqdn) {
		_adcli_info (enroll->conn, "Using fully qualified name: %s",
		             enroll->host_fqdn);
		return ADCLI_SUCCESS;
	}

	if (enroll->host_fqdn_explicit) {
		_adcli_info (enroll->conn, "Not setting fully qualified name");
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
	const char *dom;

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->computer_name) {
		_adcli_info (enroll->conn, "Enrolling computer name: %s",
		             enroll->computer_name);
		return ADCLI_SUCCESS;
	}

	if (!enroll->host_fqdn) {
		_adcli_err (enroll->conn, "No host name from which to determine the computer name");
		return ADCLI_ERR_CONFIG;
	}

	/* Use the FQDN minus the last part */
	dom = strchr (enroll->host_fqdn, '.');

	/* If no dot, or dot is first or last, then fail */
	if (dom == NULL || dom == enroll->host_fqdn || dom[1] == '\0') {
		_adcli_err (enroll->conn, "Couldn't determine the computer account name from host name: %s",
		            enroll->host_fqdn);
		return ADCLI_ERR_CONFIG;
	}

	enroll->computer_name = strndup (enroll->host_fqdn, dom - enroll->host_fqdn);
	return_unexpected_if_fail (enroll->computer_name != NULL);

	_adcli_str_up (enroll->computer_name);

	_adcli_info (enroll->conn, "Enrolling computer account name calculated from fqdn: %s", enroll->computer_name);
	return ADCLI_SUCCESS;
}

static adcli_result
ensure_computer_sam (adcli_result res,
                     adcli_enroll *enroll)
{
	krb5_error_code code;
	krb5_context k5;

	free (enroll->computer_sam);
	enroll->computer_sam = NULL;

	if (asprintf (&enroll->computer_sam, "%s$", enroll->computer_name) < 0)
		return_unexpected_if_fail (enroll->computer_sam != NULL);

	k5 = adcli_conn_get_krb5_context (enroll->conn);
	return_unexpected_if_fail (k5 != NULL);

	if (enroll->computer_principal)
		krb5_free_principal (k5, enroll->computer_principal);
	enroll->computer_principal = NULL;

	code = krb5_parse_name (k5, enroll->computer_sam, &enroll->computer_principal);
	return_unexpected_if_fail (code == 0);

	code = krb5_set_principal_realm (k5, enroll->computer_principal,
	                                 adcli_conn_get_domain_realm (enroll->conn));
	return_unexpected_if_fail (code == 0);

	return ADCLI_SUCCESS;
}

static int
filter_password_chars (char *password,
                       int length)
{
	int i, j;

	/*
	 * The MS documentation says their servers only use ASCII characters
	 * between 32 and 122 inclusive. We do that as well, and filter out
	 * all other random characters.
	 */
	for (i = 0, j = 0; i < length; i++) {
		if (password[i] >= 32 && password[i] <= 122)
			password[j++] = password[i];
	}

	/* return the number of valid characters remaining */
	return j;
}

static char *
generate_host_password  (adcli_enroll *enroll,
                         size_t length)
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

		at += filter_password_chars (buffer.data, buffer.length);
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
		assert (enroll->computer_name != NULL);
		enroll->computer_password = _adcli_calc_reset_password (enroll->computer_name);
		return_unexpected_if_fail (enroll->computer_password != NULL);
		_adcli_info (enroll->conn, "Using default reset computer password");

	} else {
		enroll->computer_password = generate_host_password (enroll, length);
		return_unexpected_if_fail (enroll->computer_password != NULL);
		_adcli_info (enroll->conn, "Generated %d character computer password", length);
	}


	return ADCLI_SUCCESS;
}

static adcli_result
ensure_service_names (adcli_result res,
                      adcli_enroll *enroll)
{
	int length = 0;

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->service_names)
		return ADCLI_SUCCESS;

	/* The default ones specified by MS */
	enroll->service_names = _adcli_strv_add (enroll->service_names,
	                                         strdup ("HOST"), &length);
	enroll->service_names = _adcli_strv_add (enroll->service_names,
	                                         strdup ("RestrictedKrbHost"), &length);
	return ADCLI_SUCCESS;
}

static adcli_result
ensure_service_principals (adcli_result res,
                           adcli_enroll *enroll)
{
	krb5_context k5;
	krb5_error_code code;
	char *name;
	int length = 0;
	int count;
	int i;

	assert (enroll->service_names != NULL);
	assert (enroll->keytab_principals == NULL);

	if (res != ADCLI_SUCCESS)
		return res;

	if (!enroll->service_principals) {
		for (i = 0; enroll->service_names[i] != NULL; i++) {
			if (asprintf (&name, "%s/%s", enroll->service_names[i], enroll->computer_name) < 0)
				return_unexpected_if_reached ();
			enroll->service_principals = _adcli_strv_add (enroll->service_principals,
			                                              name, &length);

			if (enroll->host_fqdn) {
				if (asprintf (&name, "%s/%s", enroll->service_names[i], enroll->host_fqdn) < 0)
					return_unexpected_if_reached ();
				enroll->service_principals = _adcli_strv_add (enroll->service_principals,
				                                              name, &length);
			}
		}
	}

	/* Prepare the principals we're going to add to the keytab */

	return_unexpected_if_fail (enroll->service_principals);
	count = _adcli_strv_len (enroll->service_principals);

	k5 = adcli_conn_get_krb5_context (enroll->conn);
	return_unexpected_if_fail (k5 != NULL);

	enroll->keytab_principals = calloc (count + 2, sizeof (krb5_principal));

	/* First add the principal for the computer account name */
	code = krb5_copy_principal (k5, enroll->computer_principal,
	                            &enroll->keytab_principals[0]);
	return_unexpected_if_fail (code == 0);

	/* Now add the principals for all the various services */

	for (i = 0; i < count; i++) {
		code = krb5_parse_name (k5, enroll->service_principals[i],
		                        &enroll->keytab_principals[i + 1]);
		if (code != 0) {
			_adcli_err (enroll->conn,
			            "Couldn't parse kerberos service principal: %s: %s",
			            enroll->service_principals[i],
			            krb5_get_error_message (k5, code));
			return ADCLI_ERR_CONFIG;
		}

		code = krb5_set_principal_realm (k5, enroll->keytab_principals[i + 1],
		                                 adcli_conn_get_domain_realm (enroll->conn));
		return_unexpected_if_fail (code == 0);
	}

	return ADCLI_SUCCESS;
}

static adcli_result
validate_preferred_ou (adcli_enroll *enroll)
{
	const char *objectClass = "organizationalUnit";
	struct berval bv;
	const char *base;
	LDAP *ldap;
	int ret;

	assert (enroll->preferred_ou != NULL);

	if (enroll->preferred_ou_validated)
		return ADCLI_SUCCESS;

	base = adcli_conn_get_naming_context (enroll->conn);
	assert (base != NULL);

	/* If it's equal to the base, give it a pass */
	if (strcasecmp (enroll->preferred_ou, base) == 0) {
		enroll->preferred_ou_validated = 1;
		return ADCLI_SUCCESS;
	}

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	bv.bv_val = (char *)objectClass;
	bv.bv_len = strlen (objectClass);

	ret = ldap_compare_ext_s (ldap, enroll->preferred_ou,
	                          "objectClass", &bv, NULL, NULL);

	if (ret == LDAP_COMPARE_TRUE) {
		_adcli_info (enroll->conn,
		             "The computer organizational unit is valid: %s",
		             enroll->preferred_ou);
		enroll->preferred_ou_validated = 1;
		return ADCLI_SUCCESS;

	} else if (ret == LDAP_COMPARE_FALSE) {
		_adcli_err (enroll->conn,
		            "The computer organizational unit is invalid: %s",
		            enroll->preferred_ou);
		return ADCLI_ERR_CONFIG;

	} else {
		return _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                   "Couldn't check preferred organizational unit",
		                                   enroll->preferred_ou, ADCLI_ERR_DIRECTORY);
	}
}

static adcli_result
lookup_preferred_ou (adcli_enroll *enroll)
{
	char *attrs[] = { "preferredOU", NULL };
	LDAPMessage *results;
	const char *base;
	LDAP *ldap;
	int ret;

	assert (enroll->preferred_ou == NULL);

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);
	base = adcli_conn_get_naming_context (enroll->conn);
	assert (base != NULL);

	/*
	 * TODO: The objectClass here is documented, but seems like its wrong.
	 * Needs testing against a domain with the preferredOU attribute.
	 * My domain doesn't have this preferred OU attribute, so this has always
	 * failed so far.
	 */
	ret = ldap_search_ext_s (ldap, base, LDAP_SCOPE_BASE, "(objectClass=computer)",
	                         attrs, 0, NULL, NULL, NULL, -1, &results);

	if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                   "Couldn't lookup preferred organizational unit",
		                                   NULL, ADCLI_ERR_DIRECTORY);
	}

	enroll->preferred_ou = _adcli_ldap_parse_value (ldap, results, "preferredOU");
	if (enroll->preferred_ou == NULL) {
		_adcli_info (enroll->conn, "No preferred organizational unit found, "
		             "using directory base: %s", base);
		enroll->preferred_ou = strdup (base);
		return_unexpected_if_fail (enroll->preferred_ou != NULL);
	}

	ldap_msgfree (results);
	return ADCLI_SUCCESS;
}

static adcli_result
lookup_computer_container (adcli_enroll *enroll)
{
	char *attrs[] = { "wellKnownObjects", NULL };
	char *prefix = "B:32:AA312825768811D1ADED00C04FD8D5CD:";
	int prefix_len;
	LDAPMessage *results;
	LDAP *ldap;
	char **values;
	int ret;
	int i;

	assert (enroll->preferred_ou != NULL);

	if (enroll->computer_container)
		return ADCLI_SUCCESS;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	ret = ldap_search_ext_s (ldap, enroll->preferred_ou, LDAP_SCOPE_BASE,
	                         "(objectClass=*)", attrs, 0, NULL, NULL,
	                         NULL, -1, &results);

	if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                   "Couldn't lookup computer container",
		                                   NULL, ADCLI_ERR_DIRECTORY);
	}

	values = _adcli_ldap_parse_values (ldap, results, "wellKnownObjects");
	ldap_msgfree (results);

	prefix_len = strlen (prefix);
	for (i = 0; values && values[i]; i++) {
		if (strncmp (values[i], prefix, prefix_len) == 0) {
			enroll->computer_container = strdup (values[i] + prefix_len);
			return_unexpected_if_fail (enroll->computer_container != NULL);
			_adcli_info (enroll->conn, "Found well known computer container at: %s",
			             enroll->computer_container);
			break;
		}
	}

	_adcli_strv_free (values);

	/* Try harder */
	if (!enroll->computer_container) {
		ret = ldap_search_ext_s (ldap, enroll->preferred_ou, LDAP_SCOPE_BASE,
		                         "(&(objectClass=container)(cn=Computers))",
		                         attrs, 0, NULL, NULL, NULL, -1, &results);
		if (ret == LDAP_SUCCESS) {
			enroll->computer_container = _adcli_ldap_parse_dn (ldap, results);
			if (enroll->computer_container) {
				_adcli_info (enroll->conn, "Well known computer container not "
				             "found, but found suitable one at: %s",
				             enroll->computer_container);
			}
		}

		ldap_msgfree (results);
	}

	if (!enroll->computer_container) {
		_adcli_warn (enroll->conn, "Couldn't find a computer container in the ou, "
		             "creating computer account directly in: %s", enroll->preferred_ou);
		enroll->computer_container = strdup (enroll->preferred_ou);
		return_unexpected_if_fail (enroll->computer_container != NULL);
	}

	return ADCLI_SUCCESS;
}

static adcli_result
calc_computer_account (adcli_enroll *enroll)
{
	assert (enroll->computer_container);

	free (enroll->computer_dn);
	enroll->computer_dn = NULL;

	if (asprintf (&enroll->computer_dn, "CN=%s,%s", enroll->computer_name, enroll->computer_container) < 0)
		return_unexpected_if_reached ();

	_adcli_info (enroll->conn, "Calculated computer DN: %s", enroll->computer_dn);
	return ADCLI_SUCCESS;
}

static char *
concat_mod_attr_types (LDAPMod **mods)
{
	char **names;
	int names_len;
	char *string;
	int i;

	names = NULL;
	names_len = 0;

	for (i = 0; mods[i] != NULL; i++)
		names = _adcli_strv_add (names, strdup (mods[i]->mod_type), &names_len);
	string = _adcli_strv_join (names, ", ");

	_adcli_strv_free (names);
	return string;
}

static adcli_result
create_computer_account (adcli_enroll *enroll,
                         LDAP *ldap,
                         LDAPMod **mods)
{
	char *attrs;
	int ret;

	/* Don't set blank attributes */
	mods = _adcli_ldap_prune_empty_mods (mods);
	return_unexpected_if_fail (mods);

	attrs = concat_mod_attr_types (mods);
	_adcli_info (enroll->conn, "Creating computer account with attributes: %s", attrs);
	free (attrs);

	ret = ldap_add_ext_s (ldap, enroll->computer_dn, mods, NULL, NULL);

	/* Reallocated above */
	free (mods);

	/*
	 * Hand to head. This is really dumb... AD returns
	 * OBJECT_CLASS_VIOLATION when the 'admin' account doesn't have
	 * enough permission to create this computer account.
	 *
	 * TODO: Perhaps some missing attributes are auto-generated when
	 * the administrative credentials have sufficient permissions, and
	 * those missing attributes cause the object class violation. However
	 * I've tried to screw around with this, and can't find the missing
	 * attributes. They may be hidden, like unicodePwd.
	 */

	if (ret == LDAP_INSUFFICIENT_ACCESS || ret == LDAP_OBJECT_CLASS_VIOLATION) {
		return _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                   "Insufficient permissions to modify computer account",
		                                   enroll->computer_dn,
		                                   ADCLI_ERR_CREDENTIALS);

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                   "Couldn't create computer account",
		                                   enroll->computer_dn,
		                                   ADCLI_ERR_DIRECTORY);
	}

	_adcli_info (enroll->conn, "Created computer account: %s", enroll->computer_dn);
	return ADCLI_SUCCESS;
}

static adcli_result
modify_computer_account (adcli_enroll *enroll,
                         LDAP *ldap,
                         LDAPMod **mods)
{
	char *attrs;
	int ret;
	int i;

	attrs = concat_mod_attr_types (mods);
	_adcli_info (enroll->conn, "Modifying computer account attributes: %s", attrs);
	free (attrs);

	/* Update all attributes to replace those in the directory */
	for (i = 0; mods[i] != NULL; i++)
		mods[i]->mod_op |= LDAP_MOD_REPLACE;

	ret = ldap_modify_ext_s (ldap, enroll->computer_dn, mods, NULL, NULL);
	if (ret == LDAP_INSUFFICIENT_ACCESS) {
		return _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                   "Insufficient permissions to modify computer account",
		                                   enroll->computer_dn,
		                                   ADCLI_ERR_CREDENTIALS);

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                   "Couldn't modify computer account",
		                                   enroll->computer_dn,
		                                   ADCLI_ERR_DIRECTORY);
	}

	_adcli_info (enroll->conn, "Updated existing computer account: %s", enroll->computer_dn);
	return ADCLI_SUCCESS;
}

static int
filter_for_necessary_updates (adcli_enroll *enroll,
                              LDAP *ldap,
                              LDAPMessage *results,
                              LDAPMod **mods)
{
	LDAPMessage *entry;
	struct berval **vals;
	int match;
	int out;
	int in;

	entry = ldap_first_entry (ldap, results);
	for (in = 0, out = 0; mods[in] != NULL; in++) {
		match = 0;

		/* If no entry, then no filtering */
		if (entry != NULL) {
			vals = ldap_get_values_len (ldap, entry, mods[in]->mod_type);
			if (vals != NULL) {
				match = _adcli_ldap_have_mod (mods[in], vals);
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
create_or_update_computer_account (adcli_enroll *enroll,
                                   int allow_overwrite)
{
	char *vals_objectClass[] = { "computer", NULL };
	LDAPMod objectClass = { 0, "objectClass", { vals_objectClass, } };
	char *vals_sAMAccountName[] = { enroll->computer_sam, NULL };
	LDAPMod sAMAccountName = { 0, "sAMAccountName", { vals_sAMAccountName, } };
	char *vals_userAccountControl[] = { "69632", NULL }; /* WORKSTATION_TRUST_ACCOUNT | DONT_EXPIRE_PASSWD */
	LDAPMod userAccountControl = { 0, "userAccountControl", { vals_userAccountControl, } };

	LDAPMod *mods[] = {
		&objectClass,
		&sAMAccountName,
		&userAccountControl,
		NULL,
	};

	char *attrs[] =  {
		"objectClass",
		"sAMAccountName",
		"userAccountControl",
		NULL,
	};

	adcli_result res;
	LDAPMessage *results;
	LDAP *ldap;
	int ret;
	int i;

	assert (enroll->computer_dn != NULL);

	/* Make sure above initialization is sound */
	for (i = 0; attrs[i] != NULL; i++)
		assert (strcmp (attrs[i], mods[i]->mod_type) == 0);

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	ret = ldap_search_ext_s (ldap, enroll->computer_dn, LDAP_SCOPE_BASE,
	                         "(objectClass=*)", attrs, 0, NULL, NULL, NULL, -1,
	                         &results);

	/* No computer account, create a new one */
	if (ret == LDAP_NO_SUCH_OBJECT) {
		res = create_computer_account (enroll, ldap, mods);

	/* Have a computer account, figure out what to update */
	} else if (ret == 0) {
		if (!allow_overwrite) {
			_adcli_err (enroll->conn, "The computer account %s already exists",
			            enroll->computer_name);
			res = ADCLI_ERR_CONFIG;
		} else {
			filter_for_necessary_updates (enroll, ldap, results, mods);
			if (mods[0] != NULL)
				res = modify_computer_account (enroll, ldap, mods);
			else
				res = ADCLI_SUCCESS;
			ldap_msgfree (results);
		}

	/* A failure looking up the computer account */
	} else {
		res = _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                  "Couldn't lookup computer account",
		                                  enroll->computer_dn,
		                                  ADCLI_ERR_DIRECTORY);
	}

	return res;
}

static adcli_result
set_password_with_user_creds (adcli_enroll *enroll)
{
	krb5_error_code code;
	krb5_ccache ccache;
	krb5_context k5;
	krb5_data result_string;
	krb5_data result_code_string;
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

	code = krb5_set_password_using_ccache (k5, ccache, enroll->computer_password,
	                                       enroll->computer_principal, &result_code,
	                                       &result_code_string, &result_string);

	if (code != 0) {
		_adcli_err (enroll->conn, "Couldn't set password for computer account: %s: %s",
		            enroll->computer_sam, krb5_get_error_message (k5, code));
		/* TODO: Parse out these values */
		res = ADCLI_ERR_DIRECTORY;

	} else if (result_code != 0) {
		if (krb5_chpw_message (k5, &result_string, &message) != 0)
			message = NULL;
		_adcli_err (enroll->conn, "Cannot set computer password: %.*s%s%s", (int)result_code_string.length,
		            result_code_string.data, message ? ": " : "", message ? message : "");
		res = ADCLI_ERR_CREDENTIALS;

	} else {
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
	krb5_data result_string;
	krb5_data result_code_string;
	krb5_context k5;
	int result_code;
	adcli_result res;
	char *message;

	memset (&creds, 0, sizeof (creds));

	k5 = adcli_conn_get_krb5_context (enroll->conn);
	return_unexpected_if_fail (k5 != NULL);

	code = _adcli_kinit_computer_creds (enroll->conn, "kadmin/changepw", NULL, &creds);
	if (code != 0) {
		_adcli_err (enroll->conn, "Couldn't get change password ticket for computer account: %s: %s",
		            enroll->computer_sam, krb5_get_error_message (k5, code));
		return ADCLI_ERR_DIRECTORY;
	}

	code = krb5_change_password (k5, &creds, enroll->computer_password,
	                             &result_code, &result_code_string, &result_string);

	krb5_free_cred_contents (k5, &creds);

	if (code != 0) {
		_adcli_err (enroll->conn, "Couldn't change password for computer account: %s: %s",
		            enroll->computer_sam, krb5_get_error_message (k5, code));
		/* TODO: Parse out these values */
		res = ADCLI_ERR_DIRECTORY;

	} else if (result_code != 0) {
		if (krb5_chpw_message (k5, &result_string, &message) != 0)
			message = NULL;
		_adcli_err (enroll->conn, "Cannot change computer password: %.*s%s%s", (int)result_code_string.length,
		            result_code_string.data, message ? ": " : "", message ? message : "");
		res = ADCLI_ERR_CREDENTIALS;

	} else {
		res = ADCLI_SUCCESS;
	}

	krb5_free_data_contents (k5, &result_string);
	krb5_free_data_contents (k5, &result_code_string);

	return res;
}

static adcli_result
set_computer_password (adcli_enroll *enroll)
{
	if (adcli_conn_get_login_type (enroll->conn) == ADCLI_LOGIN_COMPUTER_ACCOUNT)
		return set_password_with_computer_creds (enroll);
	else
		return set_password_with_user_creds (enroll);
}

static adcli_result
retrieve_computer_account_info (adcli_enroll *enroll)
{
	adcli_result res = ADCLI_SUCCESS;
	unsigned long kvno;
	char *value;
	LDAP *ldap;
	char *end;
	int ret;

	char *attrs[] =  {
		"msDS-KeyVersionNumber",
		"msDS-supportedEncryptionTypes",
		"dNSHostName",
		"servicePrincipalName",
		NULL,
	};

	assert (enroll->computer_dn != NULL);
	assert (enroll->computer_attributes == NULL);

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	ret = ldap_search_ext_s (ldap, enroll->computer_dn, LDAP_SCOPE_BASE,
	                         "(objectClass=*)", attrs, 0, NULL, NULL, NULL, -1,
	                         &enroll->computer_attributes);

	if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                   "Couldn't retrieve computer account info",
		                                   enroll->computer_dn,
		                                   ADCLI_ERR_DIRECTORY);
	}

	/* Update the kvno */
	if (enroll->kvno == 0) {
		value = _adcli_ldap_parse_value (ldap, enroll->computer_attributes, "msDS-KeyVersionNumber");
		if (value != NULL) {
			kvno = strtoul (value, &end, 10);
			if (end == NULL || *end != '\0') {
				_adcli_err (enroll->conn,
				            "Invalid kvno '%s' for computer account in directory: %s",
				            value, enroll->computer_dn);
				res = ADCLI_ERR_DIRECTORY;

			} else {
				enroll->kvno = kvno;

				_adcli_info (enroll->conn,
				             "Retrieved kvno '%s' for computer account in directory: %s",
				             value, enroll->computer_dn);
			}

			free (value);

		} else {
			/* Apparently old AD didn't have this attribute, use zero */
			enroll->kvno = 0;

			_adcli_info (enroll->conn,
			             "No kvno found for computer account in directory: %s",
			             enroll->computer_dn);
		}
	}

	return res;
}

static adcli_result
update_and_calculate_enctypes (adcli_enroll *enroll)
{
	const char *value = NULL;
	krb5_enctype *read_enctypes;
	char *vals_supportedEncryptionTypes[] = { NULL, NULL };
	LDAPMod mod = { LDAP_MOD_REPLACE, "msDS-supportedEncryptionTypes", { vals_supportedEncryptionTypes, } };
	LDAPMod *mods[2] = { &mod, NULL };
	char *new_value;
	LDAP *ldap;
	int ret;

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
	 */

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	return_unexpected_if_fail (ldap != NULL);

	value = _adcli_ldap_parse_value (ldap, enroll->computer_attributes, "msDS-supportedEncryptionTypes");

	if (!enroll->keytab_enctypes_explicit) {
		if (value != NULL) {
			read_enctypes = _adcli_krb5_parse_enctypes (value);
			if (read_enctypes == NULL) {
				_adcli_warn (enroll->conn, "Invalid or unsupported encryption types are set on "
				             "the computer account (%s).", value);
			} else {
				free (enroll->keytab_enctypes);
				enroll->keytab_enctypes = read_enctypes;
			}
		}
	}

	new_value = _adcli_krb5_format_enctypes (adcli_enroll_get_keytab_enctypes (enroll));
	if (new_value == NULL) {
		_adcli_warn (enroll->conn, "The encryption types desired are not available in active directory");
		return ADCLI_ERR_CONFIG;
	}

	/* If we already have this value, then don't need to update */
	if (value && strcmp (new_value, value) == 0)
		return ADCLI_SUCCESS;

	vals_supportedEncryptionTypes[0] = new_value;

	if (filter_for_necessary_updates (enroll, ldap, enroll->computer_attributes, mods) == 0)
		ret = 0;
	else
		ret = ldap_modify_ext_s (ldap, enroll->computer_dn, mods, NULL, NULL);

	free (new_value);

	if (ret == LDAP_INSUFFICIENT_ACCESS) {
		return _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                   "Insufficient permissions to set encryption types on computer account",
		                                   enroll->computer_dn,
		                                   ADCLI_ERR_CREDENTIALS);

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                   "Couldn't set encryption types on computer account",
		                                   enroll->computer_dn,
		                                   ADCLI_ERR_DIRECTORY);
	}

	return ADCLI_SUCCESS;
}

static adcli_result
update_dns_host_name (adcli_enroll *enroll)
{
	char *vals_dNSHostName[] = { enroll->host_fqdn, NULL };
	LDAPMod dNSHostName = { LDAP_MOD_REPLACE, "dNSHostName", { vals_dNSHostName, } };
	LDAPMod *mods[] = { &dNSHostName, NULL, };
	LDAP *ldap;
	int ret;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	return_unexpected_if_fail (ldap != NULL);

	/* See if there are any changes to be made? */
	if (filter_for_necessary_updates (enroll, ldap, enroll->computer_attributes, mods) == 0)
		return ADCLI_SUCCESS;

	ret = ldap_modify_ext_s (ldap, enroll->computer_dn, mods, NULL, NULL);
	if (ret == LDAP_INSUFFICIENT_ACCESS) {
		return _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                   "Insufficient permissions to set host name on computer account",
		                                   enroll->computer_dn,
		                                   ADCLI_ERR_CREDENTIALS);

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                   "Couldn't set host name on computer account",
		                                   enroll->computer_dn,
		                                   ADCLI_ERR_DIRECTORY);
	}

	return ADCLI_SUCCESS;
}

static adcli_result
update_service_principals (adcli_enroll *enroll)
{
	LDAPMod servicePrincipalName = { LDAP_MOD_REPLACE, "servicePrincipalName", { enroll->service_principals, } };
	LDAPMod *mods[] = { &servicePrincipalName, NULL, };
	LDAP *ldap;
	int ret;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	return_unexpected_if_fail (ldap != NULL);

	/* See if there are any changes to be made? */
	if (filter_for_necessary_updates (enroll, ldap, enroll->computer_attributes, mods) == 0)
		return ADCLI_SUCCESS;

	ret = ldap_modify_ext_s (ldap, enroll->computer_dn, mods, NULL, NULL);
	if (ret == LDAP_INSUFFICIENT_ACCESS) {
		return _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                   "Insufficient permissions to set service principals on computer account",
		                                   enroll->computer_dn,
		                                   ADCLI_ERR_CREDENTIALS);

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                   "Couldn't set service principals on computer account",
		                                   enroll->computer_dn,
		                                   ADCLI_ERR_DIRECTORY);
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

	if (enroll->keytab_name) {
		code = krb5_kt_resolve (k5, enroll->keytab_name, &enroll->keytab);
		if (code != 0) {
			_adcli_err (enroll->conn, "Failed to open keytab: %s: %s",
			            enroll->keytab_name, krb5_get_error_message (k5, code));
			return ADCLI_ERR_FAIL;
		}

	} else {
		code = krb5_kt_default (k5, &enroll->keytab);
		if (code != 0) {
			_adcli_err (enroll->conn, "Failed to open default keytab: %s",
			            krb5_get_error_message (k5, code));
			return ADCLI_ERR_FAIL;
		}

		name = malloc (MAX_KEYTAB_NAME_LEN + 1);
		return_unexpected_if_fail (name != NULL);

		code = krb5_kt_get_name (k5, enroll->keytab, name, MAX_KEYTAB_NAME_LEN + 1);
		return_unexpected_if_fail (code == 0);

		enroll->keytab_name = name;
		enroll->keytab_name_is_krb5 = 1;
	}

	_adcli_info (enroll->conn, "Using keytab: %s", enroll->keytab_name);
	return ADCLI_SUCCESS;
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
	code = _adcli_krb5_w2k3_salt (k5, principal, enroll->computer_name, &salts[i++]);
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
add_principal_to_keytab (adcli_enroll *enroll,
                         krb5_context k5,
                         krb5_principal principal,
                         const char *principal_name,
                         int *which_salt)
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
		_adcli_err (enroll->conn, "Couldn't update keytab: %s: %s",
		            enroll->keytab_name, krb5_get_error_message (k5, code));
		return ADCLI_ERR_FAIL;
	}

	if (closure.matched) {
		_adcli_info (enroll->conn, "Cleared old entries from keytab: %s",
		             enroll->keytab_name);
	}

	password.data = enroll->computer_password;
	password.length = strlen (enroll->computer_password);

	enctypes = adcli_enroll_get_keytab_enctypes (enroll);

	/*
	 * So we need to discover which salt to use. As a side effect we are
	 * also testing that our account works.
	 */

	salts = build_principal_salts (enroll, k5, principal);
	return_unexpected_if_fail (salts != NULL);

	if (*which_salt < 0) {
		code = _adcli_krb5_keytab_discover_salt (k5, principal, enroll->kvno, &password,
		                                         enctypes, salts, which_salt);
		if (code != 0) {
			_adcli_err (enroll->conn,
			            "Couldn't authenticate with keytab while discover which salt to use: %s: %s",
			            principal_name, krb5_get_error_message (k5, code));
			free_principal_salts (k5, salts);
			return ADCLI_ERR_DIRECTORY;
		}

		assert (*which_salt >= 0);
		_adcli_info (enroll->conn, "Discovered which keytab salt to use");
	}

	code = _adcli_krb5_keytab_add_entries (k5, enroll->keytab, principal,
	                                       enroll->kvno, &password, enctypes, &salts[*which_salt]);

	free_principal_salts (k5, salts);

	if (code != 0) {
		_adcli_err (enroll->conn,
		            "Couldn't add keytab entries: %s: %s",
		            enroll->keytab_name, krb5_get_error_message (k5, code));
		return ADCLI_ERR_FAIL;
	}


	_adcli_info (enroll->conn, "Added the entries to the keytab: %s: %s",
	             principal_name, enroll->keytab_name);
	return ADCLI_SUCCESS;
}

static adcli_result
update_keytab_for_principals (adcli_enroll *enroll)
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
		                               name, &which_salt);
		krb5_free_unparsed_name (k5, name);

		if (res != ADCLI_SUCCESS)
			return res;
	}

	return ADCLI_SUCCESS;
}

static void
enroll_clear_state (adcli_enroll *enroll)
{
	krb5_context k5;
	int i;

	if (enroll->keytab_principals) {
		k5 = adcli_conn_get_krb5_context (enroll->conn);
		return_if_fail (k5 != NULL);

		for (i = 0; enroll->keytab_principals[i] != NULL; i++)
			krb5_free_principal (k5, enroll->keytab_principals[i]);

		free (enroll->keytab_principals);
		enroll->keytab_principals = NULL;
	}

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

	if (!enroll->service_principals_explicit) {
		_adcli_strv_free (enroll->service_principals);
		enroll->service_principals = NULL;
	}

	enroll->kvno = 0;

	if (enroll->computer_attributes) {
		ldap_msgfree (enroll->computer_attributes);
		enroll->computer_attributes = NULL;
	}
}

adcli_result
adcli_enroll_prepare (adcli_enroll *enroll,
                      adcli_enroll_flags flags)
{
	adcli_result res = ADCLI_SUCCESS;

	return_unexpected_if_fail (enroll != NULL);

	adcli_conn_clear_last_error (enroll->conn);

	/* Basic discovery and figuring out enroll params */
	res = ensure_host_fqdn (res, enroll);
	res = ensure_computer_name (res, enroll);
	res = ensure_computer_sam (res, enroll);
	res = ensure_computer_password (res, enroll);
	if (!(flags & ADCLI_ENROLL_NO_KEYTAB))
		res = ensure_host_keytab (res, enroll);
	res = ensure_service_names (res, enroll);
	res = ensure_service_principals (res, enroll);

	return res;
}

adcli_result
adcli_enroll_join (adcli_enroll *enroll,
                   adcli_enroll_flags flags)
{
	adcli_result res = ADCLI_SUCCESS;

	return_unexpected_if_fail (enroll != NULL);

	adcli_conn_clear_last_error (enroll->conn);
	enroll_clear_state (enroll);

	res = adcli_conn_discover (enroll->conn);
	if (res != ADCLI_SUCCESS)
		return res;

	res = adcli_enroll_prepare (enroll, flags);
	if (res != ADCLI_SUCCESS)
		return res;

	res = adcli_conn_connect (enroll->conn);
	if (res != ADCLI_SUCCESS)
		return res;

	/* Figure out where to place the computer account */
	if (enroll->computer_dn == NULL) {

		/* Now we need to find or validate the preferred ou */
		if (enroll->preferred_ou)
			res = validate_preferred_ou (enroll);
		else
			res = lookup_preferred_ou (enroll);
		if (res != ADCLI_SUCCESS)
			return res;

		/* Now need to find or validate the computer container */
		res = lookup_computer_container (enroll);
		if (res != ADCLI_SUCCESS)
			return res;

		res = calc_computer_account (enroll);
		if (res != ADCLI_SUCCESS)
			return res;
	}

	/* This is where it really happens */
	res = create_or_update_computer_account (enroll, flags & ADCLI_ENROLL_ALLOW_OVERWRITE);
	if (res != ADCLI_SUCCESS)
		return res;

	res = set_computer_password (enroll);
	if (res != ADCLI_SUCCESS)
		return res;

	/* Get information about the computer account */
	res = retrieve_computer_account_info (enroll);
	if (res != ADCLI_SUCCESS)
		return res;

	/* We ignore failures of setting these fields */
	update_and_calculate_enctypes (enroll);
	update_dns_host_name (enroll);
	update_service_principals (enroll);

	if (flags & ADCLI_ENROLL_NO_KEYTAB)
		return ADCLI_SUCCESS;

	/*
	 * Salting in the keytab is wild, we need to autodetect the format
	 * that we use for salting.
	 */

	return update_keytab_for_principals (enroll);
}

adcli_enroll *
adcli_enroll_new (adcli_conn *conn)
{
	adcli_enroll *enroll;

	return_val_if_fail (conn != NULL, NULL);

	enroll = calloc (1, sizeof (adcli_enroll));
	return_val_if_fail (enroll != NULL, NULL);

	enroll->conn = adcli_conn_ref (conn);
	enroll->refs = 1;
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
	free (enroll->preferred_ou);
	free (enroll->computer_container);
	free (enroll->computer_dn);
	free (enroll->keytab_enctypes);

	_adcli_strv_free (enroll->service_names);
	_adcli_strv_free (enroll->service_principals);
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
adcli_enroll_get_computer_name (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->computer_name;
}

void
adcli_enroll_set_computer_name (adcli_enroll *enroll,
                                const char *value)
{
	return_if_fail (enroll != NULL);
	_adcli_str_set (&enroll->computer_name, value);
	enroll->computer_name_explicit = (value != NULL);
}

const char *
adcli_enroll_get_preferred_ou (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->preferred_ou;
}

void
adcli_enroll_set_preferred_ou (adcli_enroll *enroll,
                               const char *value)
{
	return_if_fail (enroll != NULL);

	enroll->preferred_ou_validated = 0;
	_adcli_str_set (&enroll->preferred_ou, value);
}

const char *
adcli_enroll_get_computer_container (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->computer_container;
}

void
adcli_enroll_set_computer_container (adcli_enroll *enroll,
                                     const char *value)
{
	return_if_fail (enroll != NULL);
	_adcli_str_set (&enroll->computer_container, value);
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

	if (value) {
		newval = strdup (value);
		return_if_fail (newval != NULL);
	}

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

	enroll->keytab_name = newval;
	enroll->keytab_name_is_krb5 = 0;
}

krb5_enctype *
adcli_enroll_get_keytab_enctypes (adcli_enroll *enroll)
{
	static krb5_enctype default_enctypes[] = {
		ENCTYPE_AES256_CTS_HMAC_SHA1_96,
		ENCTYPE_AES128_CTS_HMAC_SHA1_96,
		ENCTYPE_DES3_CBC_SHA1,
		ENCTYPE_ARCFOUR_HMAC,
		ENCTYPE_DES_CBC_MD5,
		ENCTYPE_DES_CBC_CRC,
		0
	};

	return_val_if_fail (enroll != NULL, NULL);
	if (enroll->keytab_enctypes)
		return enroll->keytab_enctypes;
	return default_enctypes;
}

void
adcli_enroll_set_keytab_enctypes (adcli_enroll *enroll,
                                  krb5_enctype *value)
{
	krb5_enctype *newval = NULL;
	int len;

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
