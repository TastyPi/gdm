/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright  (C) 2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */
#include <config.h>

#include <unistd.h>

#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include <security/pam_misc.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>

#ifdef HAVE_KEYUTILS
#include <keyutils.h>
#endif

int
pam_sm_authenticate (pam_handle_t  *pamh,
                     int            flags,
                     int            argc,
                     const char   **argv)
{
#ifdef HAVE_KEYUTILS
        int r;
        char *cached_passwords = NULL;
        char *last_cached_password = NULL;
        key_serial_t serial;

        serial = find_key_by_type_and_desc ("user", "cryptsetup", 0);
        if (serial == 0)
                return PAM_AUTHINFO_UNAVAIL;

        r = keyctl_read_alloc (serial, &cached_passwords);
        if (r < 0)
                return PAM_AUTHINFO_UNAVAIL;

        // Find the last password in the NUL-separated list of passwords.
        // Multiple passwords are returned either when the user enters an
        // incorrect password or there are multiple encrypted drives.
        // In the case of an incorrect password the last one is correct.
        // In the case of multiple drives, choosing the last drive is as
        // arbitrary a choice as any other, but choosing the last password at
        // least supports multiple attempts on the last drive.
        last_cached_password = cached_passwords;
        for (char *c = cached_passwords; c < cached_passwords + r - 1; ++c) {
                if (*c == 0)
                        last_cached_password = c + 1;
        }

        r = pam_set_item (pamh, PAM_AUTHTOK, last_cached_password);

        free (cached_passwords);

        if (r < 0)
                return PAM_AUTH_ERR;
        else
                return PAM_SUCCESS;
#endif

        return PAM_AUTHINFO_UNAVAIL;
}

int
pam_sm_setcred (pam_handle_t *pamh,
                int           flags,
                int           argc,
                const char  **argv)
{
        return PAM_SUCCESS;
}

int
pam_sm_acct_mgmt (pam_handle_t  *pamh,
                  int            flags,
                  int            argc,
                  const char   **argv)
{
        return PAM_SUCCESS;
}

int
pam_sm_chauthtok (pam_handle_t  *pamh,
                  int            flags,
                  int            argc,
                  const char   **argv)
{
        return PAM_SUCCESS;
}

int
pam_sm_open_session (pam_handle_t  *pamh,
                     int            flags,
                     int            argc,
                     const char   **argv)
{
        return PAM_SUCCESS;
}

int
pam_sm_close_session (pam_handle_t  *pamh,
                      int            flags,
                      int            argc,
                      const char   **argv)
{
        return PAM_SUCCESS;
}
