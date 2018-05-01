/*
 * Based on Alternate Getty (agetty) 'agetty' is a versatile, portable, easy to use
 * replacement for getty. This adds ncurses to agetty.
 *
 * This program is freely distributable.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdarg.h>
#include <ctype.h>
#include <utmpx.h>
#include <getopt.h>
#include <time.h>
#include <sys/socket.h>
#include <langinfo.h>
#include <pwd.h>
#include <grp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "strutils.h"
#include "all-io.h"
#include "nls.h"
#include "pathnames.h"
#include "c.h"
#include "widechar.h"
#include "ttyutils.h"
#include "color-names.h"
#include "env.h"
#include "setproctitle.h"
#include "env.h"
#include "xalloc.h"
#include "all-io.h"
#include "fileutils.h"
#include "pwdutils.h"

#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#include <syslog.h>
#include <lastlog.h>

#ifdef __linux__
#  include <sys/kd.h>
#  ifndef DEFAULT_VCTERM
#    define DEFAULT_VCTERM "linux"
#  endif
#  ifndef DEFAULT_STERM
#    define DEFAULT_STERM  "vt102"
#  endif
#endif

#include <sys/sendfile.h>

/*
 * Some heuristics to find out what environment we are in: if it is not
 * System V, assume it is SunOS 4. The LOGIN_PROCESS is defined in System V
 * utmp.h, which will select System V style getty.
 */
#ifdef LOGIN_PROCESS
#  define SYSV_STYLE
#endif
#define DEBUGGING 1

struct options {
	int           flags;			/* toggle switches, see below */
	char         *tty;			    /* name of tty */
	char         *vcline;			/* line of virtual console */
	char         *term;	    		/* terminal type */
	int           clocal;			/* CLOCAL_MODE_* */
};

enum {
	CLOCAL_MODE_AUTO = 0,
	CLOCAL_MODE_ALWAYS,
	CLOCAL_MODE_NEVER
};


#define F_KEEPCFLAGS   (1<<10)	/* reuse c_cflags setup from kernel */
#define F_VCONSOLE	   (1<<12)	/* This is a virtual console */
#define F_HANGUP	   (1<<13)	/* Do call vhangup(2) */
#define F_NOCLEAR	   (1<<16)  /* Do not clear the screen before prompting */

#define serial_tty_option(opt, flag)	\
	(((opt)->flags & (F_VCONSOLE|(flag))) == (flag))

static void parse_args(int argc, char **argv, struct options *op);
static void update_utmp(struct options *op);
static void open_tty(char *tty, struct termios *tp, struct options *op);
static void termio_init(struct options *op, struct termios *tp);
static void reset_vc (const struct options *op, struct termios *tp);
static void termio_final(struct options *op,
						 struct termios *tp, struct chardata *cp);
static void usage(void) __attribute__((__noreturn__));
static void exit_slowly(int code) __attribute__((__noreturn__));
static void log_err(const char *, ...) __attribute__((__noreturn__))
				   __attribute__((__format__(printf, 1, 2)));
static void log_warn (const char *, ...)
				__attribute__((__format__(printf, 1, 2)));
static void print_issue_file(struct options *op, struct termios *tp);

#ifdef DEBUGGING
# include "closestream.h"
# ifndef DEBUG_OUTPUT
#  define DEBUG_OUTPUT "/dev/tty10"
# endif
# define debug(s) do { fprintf(dbf,s); fflush(dbf); } while (0)
FILE *dbf;
#else
# define debug(s) do { ; } while (0)
#endif

#include <form.h>
#include <menu.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <ctype.h>

#define NUM_FIELDS                                      0
#define NUM_ITEMS                                       3

#define USER_ROW                                        9
#define PSWD_ROW                             (USER_ROW+2)
#define OPTIONS_ROW                          (PSWD_ROW+3)
#define START_TEXT_COL                                 24
#define TEXT_SIZE                                      12
#define START_INPUT_COL                                36
#define INPUT_SIZE                                     12
#define DEFAULT_WIN_WIDTH                            COLS
#define DEFAULT_WIN_HEIGHT                          LINES
#define DEFAULT_FIELD_HEIGHT                            1

#define DEFAULT_WINDOW_START_ROW                        0
#define DEFAULT_WINDOW_START_COL                        0

#define FORM_WINDOW_HEIGHT                (OPTIONS_ROW-1)
#define FORM_WINDOW_WIDTH               DEFAULT_WIN_WIDTH
#define FORM_WINDOW_START_ROW    DEFAULT_WINDOW_START_ROW
#define FORM_WINDOW_START_COL    DEFAULT_WINDOW_START_COL

#define FORM_SUBWIN_HEIGHT                             10
#define FORM_SUBWIN_WIDTH                              40
#define FORM_SUBWIN_START_ROW                (USER_ROW-1)
#define FORM_SUBWIN_START_COL          (START_TEXT_COL-2)

#define MENU_WINDOW_HEIGHT                             5
#define MENU_WINDOW_WIDTH                              70
#define MENU_WINDOW_START_ROW             (OPTIONS_ROW-1)
#define MENU_WINDOW_START_COL                          27

#define DONE_TEXT                         "Start Install"
#define CANCEL_TEXT                       "Exit To Shell"

typedef struct login_ui_s {
	int      numitems;
	ITEM   **itms;
	MENU    *menu;
	WINDOW  *bodywin;
	WINDOW  *menuwin;
} login_ui_t;

login_ui_t *setup_first_screen(void);
int button_handle(ITEM *item);
void run_ui_loop(login_ui_t *lui);
int teardown_first_screen(login_ui_t *lui);
void login_now(int argc, char **argv);

login_ui_t *setup_first_screen(void)
{
	login_ui_t *lui;
	//WINDOW *tmpw1;

	/* Initialize curses */
	initscr();
	start_color();
	cbreak();
	curs_set(0);
	noecho();
	keypad(stdscr, TRUE);

	init_pair(1, COLOR_WHITE, COLOR_BLUE);
	init_pair(2, COLOR_WHITE, COLOR_BLUE);

	lui   = malloc(sizeof(login_ui_t));
	lui->numitems  = NUM_ITEMS;
	lui->bodywin = newwin(DEFAULT_WIN_HEIGHT, DEFAULT_WIN_WIDTH, DEFAULT_WINDOW_START_ROW, DEFAULT_WINDOW_START_COL);
	assert(lui->bodywin != NULL);
	//box(lui->formwin, 0, 0);
	//lui->menuwin = newwin(2, 12, MENU_ROW, 30);
	lui->menuwin = derwin(lui->bodywin, MENU_WINDOW_HEIGHT, MENU_WINDOW_WIDTH, MENU_WINDOW_START_ROW, MENU_WINDOW_START_COL);
	assert(lui->menuwin != NULL);
	box(lui->menuwin, 0, 0);
	//lui->menuwin = newwin(2, 12, MENU_ROW, 30);
	//tmpw1 = derwin(lui->formwin, 10, 40, USER_ROW-1, START_TEXT_COL-2);
	//box(tmpw1, 0, 0);
	//set_form_sub(lui->iform, tmpw1);
	//refresh();
	
	lui->itms = (ITEM **)calloc(lui->numitems, sizeof(ITEM *));
	assert(lui->itms != NULL);
	lui->itms[0] = new_item(CANCEL_TEXT, CANCEL_TEXT);
	lui->itms[1] = new_item(DONE_TEXT, DONE_TEXT);
	lui->itms[2] = (ITEM*)NULL;
	assert(lui->itms[0] != NULL);
	assert(lui->itms[1] != NULL);

	keypad(lui->menuwin, TRUE);
	//refresh();
	lui->menu = new_menu((ITEM **)lui->itms);
	assert(lui->menu != NULL);
	menu_opts_off(lui->menu, O_SHOWDESC);
	menu_opts_off(lui->menu, O_ROWMAJOR);
	set_menu_win(lui->menu, lui->menuwin);
	set_menu_format(lui->menu, 4, 0);
	set_menu_mark(lui->menu, "");

	//form_driver (lui->iform, REQ_CLR_FIELD);


	post_menu(lui->menu);
	//refresh();
	wrefresh(lui->bodywin);
	wrefresh(lui->menuwin);

	return lui;
}

int button_handle(ITEM *item)
{
	 const char *name = item_name(item);

	 if (strcmp(name, DONE_TEXT) == 0) {
		debug("Should exit now, trying...\n");
		sleep(10);
                return 1;
	 } else if (strcmp(name, CANCEL_TEXT) == 0) {
		debug("Cancel..cancel..cancel\n");
	 } else {
		exit(1);
	 }
	 return 0;
}


void run_ui_loop(login_ui_t *lui)
{
	int ch;
	int stop = 0;

	curs_set(1);
	/* Loop through to get user requests */
	while (stop != 1 && (ch = wgetch(lui->menuwin)) != KEY_ENTER)
	{
		//printf("Got ch: %x, UP is %x down %x\n", ch, KEY_UP, KEY_DOWN);
		switch(ch) {
		case KEY_DOWN:
			menu_driver(lui->menu, REQ_NEXT_ITEM);
			break;
		case KEY_UP:
			menu_driver(lui->menu, REQ_PREV_ITEM);
			break;
		case 10:
			if (button_handle(current_item(lui->menu)) == 1) {
			    stop = 1;
			    break;
			}
		}
		//refresh();
		wrefresh(lui->bodywin);
		wrefresh(lui->menuwin);
	}
	debug("Returning from ui_loop\n");
}

int teardown_first_screen(login_ui_t *lui)
{
	/* Un post form and free the memory */

	for (int i = 0; i < lui->numitems; i++)
		free_item(lui->itms[i]);

	free_menu(lui->menu);

	delwin(lui->menuwin);
	delwin(lui->bodywin);

	/* remove menus and also free lui */
	free(lui->itms);
	free(lui);

	endwin();
	return 0;
}

/*int main()
{
	login_ui_t *lui;

	lui = setup_first_screen();
	run_ui_loop(lui);
	teardown_first_screen(lui);
}*/

#ifdef USE_TTY_GROUP
# define TTY_MODE 0620
#else
# define TTY_MODE 0600
#endif

#define	TTYGRPNAME	     	"tty"	/* name of group to own ttys */
#define VCS_PATH_MAX		  64
#define PRG_NAME       "bangetty"

/*
 * Login control struct
 */
struct login_context {
	const char	    *tty_path;	           /* ttyname() return value */
	const char	    *tty_name;	           /* tty_path without /dev prefix */
	const char	    *tty_number;	       /* end of the tty_path */
	mode_t		     tty_mode;	           /* chmod() mode */
	char		    *username;	           /* from command line or PAM */
	struct passwd   *pwd;	               /* user info */
	char		    *pwdbuf;	           /* pwd strings */
	pid_t		     pid;
	int		         quiet;		           /* 1 if hush file exists */
	int		         noauth;
};

/*
 * This bounds the time given to login.  Not a define, so it can
 * be patched on machines where it's too small.
 */
static int child_pid = 0;
static volatile int got_sig = 0;

/*
 * Let us delay all exit() calls when the user is not authenticated
 * or the session not fully initialized (loginpam_session()).
 */
static void __attribute__ ((__noreturn__)) sleepexit(int eval)
{
	//sleep((unsigned int)getlogindefs_num("FAIL_DELAY", LOGIN_EXIT_TIMEOUT));
	sleep(10);
	exit(eval);
}

/*
 * Output the /etc/motd file.
 *
 * It determines the name of a login announcement file and outputs it to the
 * user's terminal at login time.  The MOTD_FILE configuration option is a
 * colon-delimited list of filenames.  An empty MOTD_FILE option disables
 * message-of-the-day printing completely.
 */
static void motd(void)
{
	char *motdlist, *motdfile;
	const char *mb;

	mb = getenv("MOTD_FILE");
	if (!mb || !*mb)
		return;

	motdlist = xstrdup(mb);

	for (motdfile = strtok(motdlist, ":"); motdfile;
		 motdfile = strtok(NULL, ":")) {

		struct stat st;
		int fd;

		fd = open(motdfile, O_RDONLY, 0);
		if (fd < 0)
			continue;
		if (!fstat(fd, &st) && st.st_size)
			sendfile(fileno(stdout), fd, NULL, st.st_size);
		close(fd);
	}

	free(motdlist);
}

#define chown_err(_what, _uid, _gid) \
		syslog(LOG_ERR, _("chown (%s, %lu, %lu) failed: %m"), \
			(_what), (unsigned long) (_uid), (unsigned long) (_gid))

#define chmod_err(_what, _mode) \
		syslog(LOG_ERR, _("chmod (%s, %u) failed: %m"), (_what), (_mode))

static void chown_tty(struct login_context *cxt)
{
	const char *grname, *gidstr;
	uid_t uid = cxt->pwd->pw_uid;
	gid_t gid = cxt->pwd->pw_gid;

	grname = getenv("TTYGROUP");
	if (grname && *grname) {
		struct group *gr = getgrnam(grname);
		if (gr)	/* group by name */
			gid = gr->gr_gid;
		else {	/* group by ID */
			gidstr = getenv("TTYGROUP");
			gid    = (gid_t) atoi(gidstr);
		}
	}
	if (fchown(0, uid, gid))				/* tty */
		chown_err(cxt->tty_name, uid, gid);
	if (fchmod(0, cxt->tty_mode))
		chmod_err(cxt->tty_name, cxt->tty_mode);
}

/*
 * Reads the current terminal path and initializes cxt->tty_* variables.
 */
static void init_tty(struct login_context *cxt)
{
	char *ttymodestr;
	struct stat st;
	struct termios tt, ttt;

	ttymodestr    = getenv("TTYPERM");
	cxt->tty_mode = (mode_t) atoi(ttymodestr);

	get_terminal_name(&cxt->tty_path, &cxt->tty_name, &cxt->tty_number);

	/*
	 * In case login is suid it was possible to use a hardlink as stdin
	 * and exploit races for a local root exploit. (Wojciech Purczynski).
	 *
	 * More precisely, the problem is  ttyn := ttyname(0); ...; chown(ttyn);
	 * here ttyname() might return "/tmp/x", a hardlink to a pseudotty.
	 * All of this is a problem only when login is suid, which it isn't.
	 */
	if (!cxt->tty_path || !*cxt->tty_path ||
		lstat(cxt->tty_path, &st) != 0 || !S_ISCHR(st.st_mode) ||
		(st.st_nlink > 1 && strncmp(cxt->tty_path, "/dev/", 5)) ||
		access(cxt->tty_path, R_OK | W_OK) != 0) {

		syslog(LOG_ERR, _("FATAL: bad tty"));
		sleepexit(EXIT_FAILURE);
	}

	tcgetattr(0, &tt);
	ttt = tt;
	ttt.c_cflag &= ~HUPCL;

	if ((fchown(0, 0, 0) || fchmod(0, cxt->tty_mode)) && errno != EROFS) {
		syslog(LOG_ERR, _("FATAL: %s: change permissions failed: %m"),
				cxt->tty_path);
		sleepexit(EXIT_FAILURE);
	}

	/* Kill processes left on this tty */
	tcsetattr(0, TCSANOW, &ttt);

	/*
	 * Let's close file descriptors before vhangup
	 * https://lkml.org/lkml/2012/6/5/145
	 */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	signal(SIGHUP, SIG_IGN);	/* so vhangup() won't kill us */
	vhangup();
	signal(SIGHUP, SIG_DFL);

	/* open stdin,stdout,stderr to the tty */
//	open_tty(cxt->tty_path);

	/* restore tty modes */
	tcsetattr(0, TCSAFLUSH, &tt);
}

static void log_lastlog(struct login_context *cxt)
{
	struct sigaction sa, oldsa_xfsz;
	struct lastlog ll;
	time_t t;
	int fd;

	if (!cxt->pwd)
		return;

	/* lastlog is huge on systems with large UIDs, ignore SIGXFSZ */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sigaction(SIGXFSZ, &sa, &oldsa_xfsz);

	fd = open(_PATH_LASTLOG, O_RDWR, 0);
	if (fd < 0)
		goto done;

	if (lseek(fd, (off_t) cxt->pwd->pw_uid * sizeof(ll), SEEK_SET) == -1)
		goto done;

	/*
	 * Print last log message.
	 */
	if (!cxt->quiet) {
		if (read(fd, (char *)&ll, sizeof(ll)) == sizeof(ll) &&
							ll.ll_time != 0) {
			time_t ll_time = (time_t) ll.ll_time;

			printf(_("Last login: %.*s "), 24 - 5, ctime(&ll_time));
			if (*ll.ll_host != '\0')
				printf(_("from %.*s\n"),
					   (int)sizeof(ll.ll_host), ll.ll_host);
			else
				printf(_("on %.*s\n"),
					   (int)sizeof(ll.ll_line), ll.ll_line);
		}
		if (lseek(fd, (off_t) cxt->pwd->pw_uid * sizeof(ll), SEEK_SET) == -1)
			goto done;
	}

	memset((char *)&ll, 0, sizeof(ll));

	time(&t);
	ll.ll_time = t;		/* ll_time is always 32bit */

	if (cxt->tty_name)
		xstrncpy(ll.ll_line, cxt->tty_name, sizeof(ll.ll_line));

	if (write_all(fd, (char *)&ll, sizeof(ll)))
		warn(_("write lastlog failed"));
done:
	if (fd >= 0)
		close(fd);

	sigaction(SIGXFSZ, &oldsa_xfsz, NULL);		/* restore original setting */
}

/*
 * Update wtmp and utmp logs.
 */
static void log_utmp(struct login_context *cxt)
{
	struct utmpx ut;
	struct utmpx *utp;
	struct timeval tv;

	utmpxname(_PATH_UTMP);
	setutxent();

	/* Find pid in utmp.
	 *
	 * login sometimes overwrites the runlevel entry in /var/run/utmp,
	 * confusing sysvinit. I added a test for the entry type, and the
	 * problem was gone. (In a runlevel entry, st_pid is not really a pid
	 * but some number calculated from the previous and current runlevel.)
	 * -- Michael Riepe <michael@stud.uni-hannover.de>
	 */
	while ((utp = getutxent()))
		if (utp->ut_pid == cxt->pid
			&& utp->ut_type >= INIT_PROCESS
			&& utp->ut_type <= DEAD_PROCESS)
			break;

	/* If we can't find a pre-existing entry by pid, try by line.
	 * BSD network daemons may rely on this. */
	if (utp == NULL && cxt->tty_name) {
		setutxent();
		ut.ut_type = LOGIN_PROCESS;
		strncpy(ut.ut_line, cxt->tty_name, sizeof(ut.ut_line));
		utp = getutxline(&ut);
	}

	/* If we can't find a pre-existing entry by pid and line, try it by id.
	 * Very stupid telnetd daemons don't set up utmp at all. (kzak) */
	if (utp == NULL && cxt->tty_number) {
		 setutxent();
		 ut.ut_type = DEAD_PROCESS;
		 strncpy(ut.ut_id, cxt->tty_number, sizeof(ut.ut_id));
		 utp = getutxid(&ut);
	}

	if (utp)
		memcpy(&ut, utp, sizeof(ut));
	else
		/* some gettys/telnetds don't initialize utmp... */
		memset(&ut, 0, sizeof(ut));

	if (cxt->tty_number && ut.ut_id[0] == 0)
		strncpy(ut.ut_id, cxt->tty_number, sizeof(ut.ut_id));
	if (cxt->username)
		strncpy(ut.ut_user, cxt->username, sizeof(ut.ut_user));
	if (cxt->tty_name)
		xstrncpy(ut.ut_line, cxt->tty_name, sizeof(ut.ut_line));

	gettimeofday(&tv, NULL);
	ut.ut_tv.tv_sec = tv.tv_sec;
	ut.ut_tv.tv_usec = tv.tv_usec;
	ut.ut_type = USER_PROCESS;
	ut.ut_pid = cxt->pid;

	pututxline(&ut);
	endutxent();

	updwtmpx(_PATH_WTMP, &ut);
}

static void log_syslog(struct login_context *cxt)
{
	struct passwd *pwd = cxt->pwd;

	if (!cxt->tty_name)
		return;

	if (!strncmp(cxt->tty_name, "ttyS", 4))
		syslog(LOG_INFO, _("DIALUP AT %s BY %s"),
			   cxt->tty_name, pwd->pw_name);

	if (!pwd->pw_uid) {
		syslog(LOG_NOTICE, _("ROOT LOGIN ON %s"), cxt->tty_name);
	} else {
		syslog(LOG_NOTICE, _("NON-ROOT LOGIN ON %s using BANGETTY!!"),
			   cxt->tty_name);
	}
}

/*
 * Detach the controlling terminal, fork, restore syslog stuff, and create
 * a new session.
 */
static void fork_session(struct login_context *cxt)
{
	struct sigaction sa, oldsa_hup, oldsa_term;

	signal(SIGQUIT, SIG_DFL);
	signal(SIGTSTP, SIG_IGN);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sigaction(SIGINT, &sa, NULL);

	sigaction(SIGHUP, &sa, &oldsa_hup);	/* ignore when TIOCNOTTY */

	/*
	 * Detach the controlling tty.
	 * We don't need the tty in a parent who only waits for a child.
	 * The child calls setsid() that detaches from the tty as well.
	 */
	ioctl(0, TIOCNOTTY, NULL);

	closelog();

	/*
	 * We must fork before setuid(), because we need to call
	 * pam_close_session() as root.
	 */
	child_pid = fork();
	if (child_pid < 0) {
		warn(_("fork failed"));

		sleepexit(EXIT_FAILURE);
	}

	if (child_pid) {
		/*
		 * parent - wait for child to finish, then clean up session
		 */
		close(0);
		close(1);
		close(2);
		//free_getlogindefs_data();

		sa.sa_handler = SIG_IGN;
		sigaction(SIGQUIT, &sa, NULL);
		sigaction(SIGINT, &sa, NULL);

		/* wait as long as any child is there */
		while (wait(NULL) == -1 && errno == EINTR) ;
		openlog(PRG_NAME, LOG_ODELAY, LOG_AUTHPRIV);
		exit(EXIT_SUCCESS);
	}

	/*
	 * child
	 */
	sigaction(SIGHUP, &oldsa_hup, NULL);		/* restore old state */
	sigaction(SIGTERM, &oldsa_term, NULL);
	if (got_sig)
		exit(EXIT_FAILURE);

	/*
	 * Problem: if the user's shell is a shell like ash that doesn't do
	 * setsid() or setpgrp(), then a ctrl-\, sending SIGQUIT to every
	 * process in the pgrp, will kill us.
	 */

	/* start new session */
	setsid();

	/* make sure we have a controlling tty */
	//open_tty(cxt->tty_path);
	openlog(PRG_NAME, LOG_ODELAY, LOG_AUTHPRIV);	/* reopen */

	/*
	 * TIOCSCTTY: steal tty from other process group.
	 */
	if (ioctl(0, TIOCSCTTY, 1))
		syslog(LOG_ERR, _("TIOCSCTTY failed: %m"));
	signal(SIGINT, SIG_DFL);
}

/*
 * Initialize $TERM, $HOME, ...
 */
static void init_environ(struct login_context *cxt)
{
	struct passwd *pwd = cxt->pwd;
	char *termenv;

	termenv = getenv("TERM");
	if (termenv)
		termenv = xstrdup(termenv);

	environ = xmalloc(sizeof(char *));
	memset(environ, 0, sizeof(char *));

	xsetenv("HOME", pwd->pw_dir, 0);	/* legal to override */
	xsetenv("USER", pwd->pw_name, 1);
	xsetenv("SHELL", pwd->pw_shell, 1);
	xsetenv("TERM", termenv ? termenv : "dumb", 1);
	free(termenv);

	if (pwd->pw_uid) {
		if (setenv("PATH", _PATH_DEFPATH, 1) != 0)
			err(EXIT_FAILURE, _("failed to set the %s environment variable"), "PATH");

	} else if (setenv("PATH", "", 1) != 0 &&
			   setenv("PATH", _PATH_DEFPATH_ROOT, 1) != 0) {
			err(EXIT_FAILURE, _("failed to set the %s environment variable"), "PATH");
	}

	/* LOGNAME is not documented in login(1) but HP-UX 6.5 does it. We'll
	 * not allow modifying it.
	 */
	xsetenv("LOGNAME", pwd->pw_name, 1);
}


void login_now(int argc, char **argv)
{
	char *childArgv[10];
	char *buff;
	int childArgc = 0;
	struct passwd *pwd;

	struct login_context cxt = {
		.tty_mode = TTY_MODE,		  /* tty chmod() */
		.pid = getpid(),		  /* PID */
	};

debug("inside login_now");
	signal(SIGQUIT, SIG_IGN);
	signal(SIGINT, SIG_IGN);

	setpriority(PRIO_PROCESS, 0, 0);
	initproctitle(argc, argv);

debug("setting username to root");
    cxt.username = malloc(10); /* XXX free, or better way to set it */
    memset(cxt.username, 0, 10);
	strcpy(cxt.username, "root");
debug("set username to root");
sleep(10);

#if 0
	for (cnt = get_fd_tabsize() - 1; cnt > 2; cnt--) 
		close(cnt);
#endif
    debug("before setpgrp");

	setpgrp();	 /* set pgid to pid this means that setsid() will fail */
    debug("after setpgrp\n");
	init_tty(&cxt);

    debug("about to open logs\n");

	openlog(PRG_NAME, LOG_ODELAY, LOG_AUTHPRIV);

    debug("logs opened\n");
	/* the user has already been authenticated */
	cxt.noauth = getuid() == 0 ? 1 : 0;

    debug("before xgetpwnam\n");
	cxt.pwd = xgetpwnam(cxt.username, &cxt.pwdbuf);
	if (!cxt.pwd) {
		warnx(_("\nSession setup problem, abort."));
		syslog(LOG_ERR, _("Invalid user name \"%s\" in %s:%d. Abort."),
			   cxt.username, __FUNCTION__, __LINE__);
		sleepexit(EXIT_FAILURE);
	}

	pwd = cxt.pwd;
	//cxt.username = pwd->pw_name;
    debug("set username cxt.username\n");

	setgroups(0, NULL);/* root */

	endpwent();

	cxt.quiet = 0;//get_hushlogin_status(pwd, 1);

	log_utmp(&cxt);
	log_lastlog(&cxt);

	chown_tty(&cxt);

	if (setgid(pwd->pw_gid) < 0 && pwd->pw_gid) {
		syslog(LOG_ALERT, _("setgid() failed"));
		exit(EXIT_FAILURE);
	}

	if (pwd->pw_shell == NULL || *pwd->pw_shell == '\0')
		pwd->pw_shell = _PATH_BSHELL;

	init_environ(&cxt);		/* init $HOME, $TERM ... */

	setproctitle(PRG_NAME, cxt.username);

	log_syslog(&cxt);

	if (!cxt.quiet) {
		motd();
	}

	/*
	 * Detach the controlling terminal, fork, and create a new session
	 * and reinitialize syslog stuff.
	 */
	fork_session(&cxt);
debug("fork done\n");

	/* discard permissions last so we can't get killed and drop core */
	if (setuid(pwd->pw_uid) < 0 && pwd->pw_uid) {
		syslog(LOG_ALERT, _("setuid() failed"));
		exit(EXIT_FAILURE);
	}

	/* wait until here to change directory! */
	if (chdir(pwd->pw_dir) < 0) {
		warn(_("%s: change directory failed"), pwd->pw_dir);

		if (chdir("/"))
			exit(EXIT_FAILURE);
		pwd->pw_dir = "/";
		printf(_("Logging in with home = \"/\".\n"));
	}

	/* if the shell field has a space: treat it like a shell script */
	if (strchr(pwd->pw_shell, ' ')) {
		buff = xmalloc(strlen(pwd->pw_shell) + 6);

		strcpy(buff, "exec ");
		strcat(buff, pwd->pw_shell);
		childArgv[childArgc++] = "/bin/sh";
		childArgv[childArgc++] = "-sh";
		childArgv[childArgc++] = "-c";
		childArgv[childArgc++] = buff;
	} else {
		char tbuf[PATH_MAX + 2], *p;

		tbuf[0] = '-';
		xstrncpy(tbuf + 1, ((p = strrchr(pwd->pw_shell, '/')) ?
					p + 1 : pwd->pw_shell), sizeof(tbuf) - 1);

		childArgv[childArgc++] = pwd->pw_shell;
		childArgv[childArgc++] = xstrdup(tbuf);
	}

	childArgv[childArgc++] = NULL;

	execvp(childArgv[0], childArgv + 1);

	if (!strcmp(childArgv[0], "/bin/sh"))
		warn(_("couldn't exec shell script"));
	else
		warn(_("no shell"));

	exit(EXIT_SUCCESS);
}

static void output_version(void)
{
	static const char *features[] = {
#ifdef DEBUGGING
		"debug",
#endif
		NULL
	};
	unsigned int i;

	printf( _("%s from %s"), program_invocation_short_name, PACKAGE_STRING);
	fputs(" (", stdout);
	for (i = 0; features[i]; i++) {
		if (0 < i)
			fputs(", ", stdout);
		printf("%s", features[i]);
	}
	fputs(")\n", stdout);
}

#define is_speed(str) (strlen((str)) == strspn((str), "0123456789,"))

/* Parse command-line arguments. */
static void parse_args(int argc, char **argv, struct options *op)
{
	int c;

	enum {
		VERSION_OPTION = CHAR_MAX + 1,
		HELP_OPTION,
	};
	const struct option longopts[] = {
		{  "version",	     no_argument,	     NULL,  'v'  },
		{  "help",	         no_argument,	     NULL,  'h'  },
		{ NULL, 0, NULL, 0 }
	};

	while ((c = getopt_long(argc, argv,
			   "hv", longopts,
				NULL)) != -1) {
		switch (c) {
		case 'v':
			output_version();
			exit(EXIT_SUCCESS);
		case 'h':
			usage();
		default:
			errtryhelp(EXIT_FAILURE);
		}
	}

	debug("after getopt loop\n");

	/* On virtual console remember the line which is used for */
	if (strncmp(op->tty, "tty", 3) == 0 &&
		strspn(op->tty + 3, "0123456789") == strlen(op->tty+3))
		op->vcline = op->tty+3;

#if 0
	if (argc > optind && argv[optind])
		op->term = argv[optind];
#endif
		op->term = 0; /* XXX hardcoded to 0 for now, Vijo */ /* FIXME wrong setting */

	debug("exiting parseargs\n");
}

#ifdef	SYSV_STYLE

/* Update our utmp entry. */
static void update_utmp(struct options *op)
{
	struct utmpx ut;
	time_t t;
	pid_t pid = getpid();
	pid_t sid = getsid(0);
	char *vcline = op->vcline;
	char *line   = op->tty;
	struct utmpx *utp;

	/*
	 * The utmp file holds miscellaneous information about things started by
	 * /sbin/init and other system-related events. Our purpose is to update
	 * the utmp entry for the current process, in particular the process type
	 * and the tty line we are listening to. Return successfully only if the
	 * utmp file can be opened for update, and if we are able to find our
	 * entry in the utmp file.
	 */
	utmpxname(_PATH_UTMP);
	setutxent();

	/*
	 * Find my pid in utmp.
	 *
	 * FIXME: Earlier (when was that?) code here tested only utp->ut_type !=
	 * INIT_PROCESS, so maybe the >= here should be >.
	 *
	 * FIXME: The present code is taken from login.c, so if this is changed,
	 * maybe login has to be changed as well (is this true?).
	 */
	while ((utp = getutxent()))
		if (utp->ut_pid == pid
				&& utp->ut_type >= INIT_PROCESS
				&& utp->ut_type <= DEAD_PROCESS)
			break;

	if (utp) {
		memcpy(&ut, utp, sizeof(ut));
	} else {
		/* Some inits do not initialize utmp. */
		memset(&ut, 0, sizeof(ut));
		if (vcline && *vcline)
			/* Standard virtual console devices */
			strncpy(ut.ut_id, vcline, sizeof(ut.ut_id));
		else {
			size_t len = strlen(line);
			char * ptr;
			if (len >= sizeof(ut.ut_id))
				ptr = line + len - sizeof(ut.ut_id);
			else
				ptr = line;
			strncpy(ut.ut_id, ptr, sizeof(ut.ut_id));
		}
	}

	strncpy(ut.ut_user, "LOGIN", sizeof(ut.ut_user));
	strncpy(ut.ut_line, line, sizeof(ut.ut_line));
	time(&t);
	ut.ut_tv.tv_sec = t;
	ut.ut_type = LOGIN_PROCESS;
	ut.ut_pid = pid;
	ut.ut_session = sid;

	pututxline(&ut);
	endutxent();

	updwtmpx(_PATH_WTMP, &ut);
}

#endif				/* SYSV_STYLE */

/* Set up tty as stdin, stdout & stderr. */
static void open_tty(char *tty, struct termios *tp, struct options *op)
{
	const pid_t pid = getpid();
	int closed = 0;
	int serial;

	/* Set up new standard input, unless we are given an already opened port. */

	if (strcmp(tty, "-") != 0) {
		char buf[PATH_MAX+1];
		struct group *gr = NULL;
		struct stat st;
		int fd, len;
		pid_t tid;
		gid_t gid = 0;

		/* Use tty group if available */
		if ((gr = getgrnam("tty")))
			gid = gr->gr_gid;

		len = snprintf(buf, sizeof(buf), "/dev/%s", tty);
		if (len < 0 || (size_t)len >= sizeof(buf))
			log_err(_("/dev/%s: cannot open as standard input: %m"), tty);

		/* Open the tty as standard input. */
		if ((fd = open(buf, O_RDWR|O_NOCTTY|O_NONBLOCK, 0)) < 0)
			log_err(_("/dev/%s: cannot open as standard input: %m"), tty);

		/*
		 * There is always a race between this reset and the call to
		 * vhangup() that s.o. can use to get access to your tty.
		 * Linux login(1) will change tty permissions. Use root owner and group
		 * with permission -rw------- for the period between getty and login.
		 */
		if (fchown(fd, 0, gid) || fchmod(fd, (gid ? 0620 : 0600))) {
			if (errno == EROFS)
				log_warn("%s: %m", buf);
			else
				log_err("%s: %m", buf);
		}

		/* Sanity checks... */
		if (fstat(fd, &st) < 0)
			log_err("%s: %m", buf);
		if ((st.st_mode & S_IFMT) != S_IFCHR)
			log_err(_("/dev/%s: not a character device"), tty);
		if (!isatty(fd))
			log_err(_("/dev/%s: not a tty"), tty);

		if (((tid = tcgetsid(fd)) < 0) || (pid != tid)) {
			if (ioctl(fd, TIOCSCTTY, 1) == -1)
				log_warn(_("/dev/%s: cannot get controlling tty: %m"), tty);
		}

		close(STDIN_FILENO);
		errno = 0;

		if (op->flags & F_HANGUP) {

			if (ioctl(fd, TIOCNOTTY))
				debug("TIOCNOTTY ioctl failed\n");

			/*
			 * Let's close all file descriptors before vhangup
			 * https://lkml.org/lkml/2012/6/5/145
			 */
			close(fd);
			close(STDOUT_FILENO);
			close(STDERR_FILENO);
			errno = 0;
			closed = 1;

			if (vhangup())
				log_err(_("/dev/%s: vhangup() failed: %m"), tty);
		} else
			close(fd);

		debug("open(2)\n");
		if (open(buf, O_RDWR|O_NOCTTY|O_NONBLOCK, 0) != 0)
			log_err(_("/dev/%s: cannot open as standard input: %m"), tty);

		if (((tid = tcgetsid(STDIN_FILENO)) < 0) || (pid != tid)) {
			if (ioctl(STDIN_FILENO, TIOCSCTTY, 1) == -1)
				log_warn(_("/dev/%s: cannot get controlling tty: %m"), tty);
		}

	} else {

		/*
		 * Standard input should already be connected to an open port. Make
		 * sure it is open for read/write.
		 */

		if ((fcntl(STDIN_FILENO, F_GETFL, 0) & O_RDWR) != O_RDWR)
			log_err(_("%s: not open for read/write"), tty);

	}

	if (tcsetpgrp(STDIN_FILENO, pid))
		log_warn(_("/dev/%s: cannot set process group: %m"), tty);

	/* Get rid of the present outputs. */
	if (!closed) {
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		errno = 0;
	}

	/* Set up standard output and standard error file descriptors. */
	debug("duping\n");

	/* set up stdout and stderr */
	if (dup(STDIN_FILENO) != 1 || dup(STDIN_FILENO) != 2)
		log_err(_("%s: dup problem: %m"), tty);

	/* make stdio unbuffered for slow modem lines */
	setvbuf(stdout, NULL, _IONBF, 0);

	memset(tp, 0, sizeof(struct termios));
	if (tcgetattr(STDIN_FILENO, tp) < 0)
		log_err(_("%s: failed to get terminal attributes: %m"), tty);

	if (ioctl(STDIN_FILENO, TIOCMGET, &serial) < 0 && (errno == EINVAL))
	{
		op->flags |= F_VCONSOLE;
		if (!op->term)
			op->term = DEFAULT_VCTERM;
	} else {
		log_err(_("%s: serial is not supported\n"), tty);
	}

	if (setenv("TERM", op->term, 1) != 0)
		log_err(_("failed to set the %s environment variable"), "TERM");
}

/* Initialize termios settings. */
static void termio_clear(int fd)
{
	/*
	 * Do not write a full reset (ESC c) because this destroys
	 * the unicode mode again if the terminal was in unicode
	 * mode.  Also it clears the CONSOLE_MAGIC features which
	 * are required for some languages/console-fonts.
	 * Just put the cursor to the home position (ESC [ H),
	 * erase everything below the cursor (ESC [ J), and set the
	 * scrolling region to the full window (ESC [ r)
	 */
	write_all(fd, "\033[r\033[H\033[J", 9);
}

/* Initialize termios settings. */
static void termio_init(struct options *op, struct termios *tp)
{
	speed_t ispeed = 0, ospeed = 0; // XXX WRONG!!
	struct winsize ws;

	if (op->flags & F_VCONSOLE) {
		setlocale(LC_CTYPE, "POSIX");
		//op->flags &= ~F_UTF8; VIJO -> FIXME
		reset_vc(op, tp);

		if ((op->flags & F_NOCLEAR) == 0)
			termio_clear(STDOUT_FILENO);
		return;
	}

	/*
	 * Initial termios settings: 8-bit characters, raw-mode, blocking i/o.
	 * Special characters are set after we have read the login name; all
	 * reads will be done in raw mode anyway. Errors will be dealt with
	 * later on.
	 */

	tp->c_iflag = 0;
	tp->c_oflag &= OPOST | ONLCR;

	if ((op->flags & F_KEEPCFLAGS) == 0)
		tp->c_cflag = CS8 | HUPCL | CREAD | (tp->c_cflag & CLOCAL);

	/*
	 * Note that the speed is stored in the c_cflag termios field, so we have
	 * set the speed always when the cflag is reset.
	 */
	cfsetispeed(tp, ispeed);
	cfsetospeed(tp, ospeed);

	/* The default is to follow setting from kernel, but it's possible
	 * to explicitly remove/add CLOCAL flag by -L[=<mode>]*/
	switch (op->clocal) {
	case CLOCAL_MODE_ALWAYS:
		tp->c_cflag |= CLOCAL;		/* -L or -L=always */
		break;
	case CLOCAL_MODE_NEVER:
		tp->c_cflag &= ~CLOCAL;		/* -L=never */
		break;
	case CLOCAL_MODE_AUTO:			/* -L=auto */
		break;
	}

#ifdef HAVE_STRUCT_TERMIOS_C_LINE
	tp->c_line = 0;
#endif
	tp->c_cc[VMIN] = 1;
	tp->c_cc[VTIME] = 0;

	/* Check for terminal size and if not found set default */
	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0) {
		if (ws.ws_row == 0)
			ws.ws_row = 24;
		if (ws.ws_col == 0)
			ws.ws_col = 80;
		if (ioctl(STDIN_FILENO, TIOCSWINSZ, &ws))
			debug("TIOCSWINSZ ioctl failed\n");
	}

	 /* Flush input and output queues, important for modems! */
	tcflush(STDIN_FILENO, TCIOFLUSH);

	if (tcsetattr(STDIN_FILENO, TCSANOW, tp))
		log_warn(_("setting terminal attributes failed: %m"));

	/* Go to blocking input even in local mode. */
	fcntl(STDIN_FILENO, F_SETFL,
		  fcntl(STDIN_FILENO, F_GETFL, 0) & ~O_NONBLOCK);

	debug("term_io 2\n");
}

/* Reset virtual console on stdin to its defaults */
static void reset_vc(const struct options *op, struct termios *tp)
{
	int fl = 0;

	fl |= (op->flags & F_KEEPCFLAGS) == 0 ? 0 : UL_TTY_KEEPCFLAGS;

	reset_virtual_console(tp, fl);

	if (tcsetattr(STDIN_FILENO, TCSADRAIN, tp))
		log_warn(_("setting terminal attributes failed: %m"));

	/* Go to blocking input even in local mode. */
	fcntl(STDIN_FILENO, F_SETFL,
		  fcntl(STDIN_FILENO, F_GETFL, 0) & ~O_NONBLOCK);
}

static void print_issue_file(struct options *op, struct termios *tp __attribute__((__unused__)))
{
	(void)op;
	/* Issue not in use, start with a new line. */
	write_all(STDOUT_FILENO, "\r\n", 2);
}

/* Set the final tty mode bits. */
static void termio_final(struct options *op, struct termios *tp, struct chardata *cp)
{
	/* General terminal-independent stuff. */

	/* 2-way flow control */
	tp->c_iflag |= IXON | IXOFF;
	tp->c_lflag |= ICANON | ISIG | ECHO | ECHOE | ECHOK | ECHOKE;
	/* no longer| ECHOCTL | ECHOPRT */
	tp->c_oflag |= OPOST;
	/* tp->c_cflag = 0; */
	tp->c_cc[VINTR] = DEF_INTR;
	tp->c_cc[VQUIT] = DEF_QUIT;
	tp->c_cc[VEOF] = DEF_EOF;
	tp->c_cc[VEOL] = DEF_EOL;
#ifdef __linux__
	tp->c_cc[VSWTC] = DEF_SWITCH;
#elif defined(VSWTCH)
	tp->c_cc[VSWTCH] = DEF_SWITCH;
#endif				/* __linux__ */

	/* Account for special characters seen in input. */
	if (cp->eol == CR) {
		tp->c_iflag |= ICRNL;
		tp->c_oflag |= ONLCR;
	}
	tp->c_cc[VERASE] = cp->erase;
	tp->c_cc[VKILL] = cp->kill;

	/* Account for the presence or absence of parity bits in input. */
	switch (cp->parity) {
	case 0:
		/* space (always 0) parity */
		break;
	case 1:
		/* odd parity */
		tp->c_cflag |= PARODD;
		/* fallthrough */
	case 2:
		/* even parity */
		tp->c_cflag |= PARENB;
		tp->c_iflag |= INPCK | ISTRIP;
		/* fallthrough */
	case (1 | 2):
		/* no parity bit */
		tp->c_cflag &= ~CSIZE;
		tp->c_cflag |= CS7;
		break;
	}
	/* Account for upper case without lower case. */
	if (cp->capslock) {
#ifdef IUCLC
		tp->c_iflag |= IUCLC;
#endif
#ifdef XCASE
		tp->c_lflag |= XCASE;
#endif
#ifdef OLCUC
		tp->c_oflag |= OLCUC;
#endif
	}

	/* Finally, make the new settings effective. */
	if (tcsetattr(STDIN_FILENO, TCSANOW, tp) < 0)
		log_err(_("%s: failed to set terminal attributes: %m"), op->tty);
}

static void __attribute__((__noreturn__)) usage(void)
{
	FILE *out = stdout;

	fputs(USAGE_HEADER, out);
	fprintf(out, _(" %1$s [options] <line> [<baud_rate>,...] [<termtype>]\n"
			   " %1$s [options] <baud_rate>,... <line> [<termtype>]\n"), program_invocation_short_name);

	fputs(USAGE_SEPARATOR, out);
	fputs(_("Open a terminal and set its mode.\n"), out);

	fputs(USAGE_OPTIONS, out);

	printf(USAGE_MAN_TAIL("agetty(8)"));

	exit(EXIT_SUCCESS);
}

/*
 * Helper function reports errors to console or syslog.
 * Will be used by log_err() and log_warn() therefore
 * it takes a format as well as va_list.
 */
#define	str2cpy(b,s1,s2)	strcat(strcpy(b,s1),s2)

static void exit_slowly(int code)
{
	/* Be kind to init(8). */
	sleep(10);
	exit(code);
}

static void log_err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	//dolog(LOG_ERR, fmt, ap);
	va_end(ap);

	exit_slowly(EXIT_FAILURE);
}

static void log_warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	//dolog(LOG_WARNING, fmt, ap);
	va_end(ap);
}

int main(int argc, char **argv)
{
	struct chardata chardata;		/* will be set by get_logname() */
	struct termios termios;			/* terminal mode bits */
	struct options options = {
		.tty    = "tty1"		/* default tty line */
	};
	//char *login_argv[LOGIN_ARGV_MAX + 1];
	//int login_argc = 0;
	struct sigaction sa, sa_hup, sa_quit, sa_int;
	sigset_t set;
	login_ui_t *lui;

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	/* In case vhangup(2) has to called */
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_RESTART;
	sigemptyset (&sa.sa_mask);
	sigaction(SIGHUP, &sa, &sa_hup);
	sigaction(SIGQUIT, &sa, &sa_quit);
	sigaction(SIGINT, &sa, &sa_int);

#ifdef DEBUGGING
	dbf = fopen(DEBUG_OUTPUT, "w");
	for (int i = 1; i < argc; i++) {
		if (i > 1)
			debug(" ");
		debug(argv[i]);
	}
	debug("\n");
#endif				/* DEBUGGING */

	/* Parse command-line arguments. */
	parse_args(argc, argv, &options);

	/* Update the utmp file before login */
#ifdef	SYSV_STYLE
	update_utmp(&options);
#endif

	debug("calling open_tty\n");

	/* Open the tty as standard { input, output, error }. */
	open_tty(options.tty, &termios, &options);

	/* Unmask SIGHUP if inherited */
	sigemptyset(&set);
	sigaddset(&set, SIGHUP);
	sigprocmask(SIG_UNBLOCK, &set, NULL);
	sigaction(SIGHUP, &sa_hup, NULL);

	tcsetpgrp(STDIN_FILENO, getpid());

	/* Initialize the termios settings (raw mode, eight-bit, blocking i/o). */
	debug("calling termio_init\n");
	termio_init(&options, &termios);

	if (options.flags & F_VCONSOLE || options.clocal != CLOCAL_MODE_ALWAYS)
		/* Go to blocking mode unless -L is specified, this change
		 * affects stdout, stdin and stderr as all the file descriptors
		 * are created by dup().   */
		fcntl(STDOUT_FILENO, F_SETFL,
			  fcntl(STDOUT_FILENO, F_GETFL, 0) & ~O_NONBLOCK);

	INIT_CHARDATA(&chardata);

	print_issue_file(&options, &termios);

	if ((options.flags & F_VCONSOLE) == 0) {
		/* Finalize the termios settings. */
		termio_final(&options, &termios, &chardata);

		/* Now the newline character should be properly written. */
		write_all(STDOUT_FILENO, "\r\n", 2);
	}

	sigaction(SIGQUIT, &sa_quit, NULL);
	sigaction(SIGINT, &sa_int, NULL);

	//free(options.osrelease);

	/* Let the login program take care of password validation. */
	//execv(options.login, login_argv);
	//log_err(_("%s: can't exec %s: %m"), options.tty, login_argv[0]);

	lui = setup_first_screen();
	run_ui_loop(lui);
	teardown_first_screen(lui);
        debug("Tore down UI screen, next login_now()\n");

	/* Also updates utmp */
	login_now(argc, argv);
#ifdef DEBUGGING
	if (close_stream(dbf) != 0)
		log_err("write failed: %s", DEBUG_OUTPUT);
#endif
}
