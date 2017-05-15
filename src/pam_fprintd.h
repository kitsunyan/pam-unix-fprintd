#ifndef _PAM_UNIX_PAM_FPRINTD_H
#define _PAM_UNIX_PAM_FPRINTD_H

#include <security/pam_modules.h>

typedef struct
{
	int interrupted;
	void *loop;
} fprintd_state;

int pam_sm_authenticate_fprintd(pam_handle_t *pamh, fprintd_state *state);

void fprintd_state_init(fprintd_state *state);
void fprintd_state_cleanup(fprintd_state *state);

#endif /* _PAM_UNIX_PAM_FPRINTD_H */
