#ifndef _PAM_UNIX_FPRINTD_BRIDGE_H
#define _PAM_UNIX_FPRINTD_BRIDGE_H

#include <security/pam_modules.h>

int get_authtok_nopasswd(pam_handle_t *pamh, int argc, const char **argv, const char **authtok, int *retval);

int verify_with_fprintd(pam_handle_t *pamh, const char **authtok, int *should_verify);

#endif /* _PAM_UNIX_FPRINTD_BRIDGE_H */
