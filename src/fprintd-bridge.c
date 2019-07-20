#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>

#include "fprintd-bridge.h"
#include "pam_fprintd.h"

#define PROMPT "Password: "
#define FPRINTD_VERIFIED "fingerprint verified"
#define FPRINTD_UNAVAILABLE "fprintd unavailable"

typedef struct
{
	pam_handle_t *pamh;
	fprintd_state *state;
	int *success;
} verify_fprintd_state;

static void * verify_fprintd(void *user_data)
{
	verify_fprintd_state *vstate = user_data;
	int retval;

	retval = pam_sm_authenticate_fprintd(vstate->pamh, vstate->state);
	*vstate->success = retval == PAM_SUCCESS;

	if (!vstate->state->interrupted && isatty(fileno(stdout)))
	{
		if (*vstate->success)
		{
			printf("[%s] ", FPRINTD_VERIFIED);
			fflush(stdout);
		}
		else if (retval == PAM_AUTHINFO_UNAVAIL)
		{
			usleep(100000);
			printf("[%s] ", FPRINTD_UNAVAILABLE);
			fflush(stdout);
		}
	}

	return NULL;
}

static void pam_prompt_fprintd(pam_handle_t *pamh, char **response, int *retval, int *fprintd_success)
{
	pthread_t thread;
	fprintd_state state;
	verify_fprintd_state vstate;

	vstate.pamh = pamh;
	vstate.state = &state;
	vstate.success = fprintd_success;
	*fprintd_success = 0;
	fprintd_state_init(&state);
	pthread_create(&thread, NULL, verify_fprintd, &vstate);
	*retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, response, "%s", PROMPT);
	fprintd_state_cleanup(&state);
	pthread_join(thread, NULL);

	if (*response && strlen(*response) > 0)
	{
		/* ignore fprintd result if something was entered */
		*fprintd_success = 0;
	}
}

static const char * get_option(pam_handle_t *pamh, int argc, const char **argv, const char *option)
{
	int i;
	size_t len;

	if (option == NULL || pamh == NULL || argc == 0 || argv == NULL)
		return NULL;

	len = strlen (option);

	for (i = 0; i < argc; i++) 
	{
		if (strncmp (option, argv[i], len) == 0)
		{
			if (argv[i][len] == '=')
				return &(argv[i][len+1]);
			else if (argv[i][len] == '\0')
				return "";
		}
	}
	return NULL;
}

int get_authtok_nopasswd(pam_handle_t *pamh, int argc, const char **argv, const char **authtok, int *retval)
{
	const void *prevauthtok;
	int tmpretval;

	if (authtok == NULL)
		return PAM_SYSTEM_ERR;

	tmpretval = pam_get_item(pamh, PAM_AUTHTOK, &prevauthtok);
	if (tmpretval == PAM_SUCCESS && prevauthtok != NULL)
	{
		*authtok = prevauthtok;
		*retval = PAM_SUCCESS;
		return 0;
	}
	else if (get_option(pamh, argc, argv, "use_first_pass") || get_option(pamh, argc, argv, "use_authtok"))
	{
		if (prevauthtok == NULL)
			*retval = PAM_AUTH_ERR;
		else
			*retval = tmpretval;
		return 0;
	}

	return 1;
}

int verify_with_fprintd(pam_handle_t *pamh, const char **authtok, int *should_verify)
{
	char *response = NULL;
	int retval;
	int fprintd_success;

	pam_prompt_fprintd(pamh, &response, &retval, &fprintd_success);
	if (fprintd_success)
	{
		*should_verify = 0;
		return PAM_SUCCESS;
	}
	if (retval != PAM_SUCCESS || response == NULL)
		return PAM_AUTHTOK_ERR;

	retval = pam_set_item(pamh, PAM_AUTHTOK, response);
	_pam_overwrite(response);
	_pam_drop(response);
	if (retval != PAM_SUCCESS)
		return retval;

	return pam_get_item(pamh, PAM_AUTHTOK, (const void **) authtok);
}
