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
#include <pwd.h>
#include <grp.h>
#include <pathnames.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <form.h>
#include <assert.h>

#include "strutils.h"
#include "all-io.h"
#include "ttyutils.h"
#include "env.h"
//#include "setproctitle.h"
#include "xalloc.h"
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

#define SYSV_STYLE
#define DEBUGGING 1

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

#ifdef USE_TTY_GROUP
# define TTY_MODE 0620
#else
# define TTY_MODE 0600
#endif

#define	TTYGRPNAME	     	"tty"	/* name of group to own ttys */
#define VCS_PATH_MAX		  64
#define PRG_NAME           "bangetty"

/*
 * Main control struct
 */
struct nlogin_context {
	char	            *tty_path;	           /* ttyname() return value */
	const char	    *tty_name;	           /* tty_path without /dev prefix */
	const char	    *tty_number;	   /* end of the tty_path */
	mode_t		     tty_mode;	           /* chmod() mode */
	char		    *username;	           /* from command line or PAM */
	struct passwd       *pwd;	           /* user info */
	char		    *pwdbuf;	           /* pwd strings */
	pid_t		     pid;
	int                  flags;	  	   /* toggle switches, see below */
	char                *tty;		   /* name of tty */
	char                *term;	    	   /* terminal type */
};

#define F_KEEPCFLAGS   (1<<10)	/* reuse c_cflags setup from kernel */
#define F_VCONSOLE	   (1<<12)	/* This is a virtual console */

static void parse_args(int argc, char **argv, struct nlogin_context *op);
static void update_utmp(struct nlogin_context *op);
static void open_tty(char *tty, struct termios *tp, struct nlogin_context *op);
static void termio_init(struct nlogin_context *op, struct termios *tp);
static void reset_vc (const struct nlogin_context *op, struct termios *tp);
static void usage(void) __attribute__((__noreturn__));
static void exit_slowly(int code) __attribute__((__noreturn__));
static void log_err(const char *, ...) __attribute__((__noreturn__))
				   __attribute__((__format__(printf, 1, 2)));
static void log_warn (const char *, ...)
				__attribute__((__format__(printf, 1, 2)));

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

#define NUM_FIELDS                                      3
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

#define MENU_WINDOW_HEIGHT                              2
#define MENU_WINDOW_WIDTH                              15
#define MENU_WINDOW_START_ROW             (OPTIONS_ROW-1)
#define MENU_WINDOW_START_COL                          27

#define DONE_TEXT                                  "Done"
#define CANCEL_TEXT                              "Cancel"

typedef struct login_ui_s {
    int      numfields;
    int      numitems;
    FIELD  **field;
    FORM    *iform;
    ITEM   **itms;
    MENU    *menu;
    WINDOW  *bodywin;
    WINDOW  *formwin;
    WINDOW  *menuwin;
} login_ui_t;

login_ui_t *setup_login_screen(void);
static char *trim_input(char *input);
int button_handle(login_ui_t *lui, ITEM *item);
void run_login_loop(login_ui_t *lui);
int teardown_login_screen(login_ui_t *lui);
void login_now(int argc, char **argv);

login_ui_t *setup_login_screen(void)
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
    lui->numfields = NUM_FIELDS;
    lui->numitems  = NUM_ITEMS;
    lui->bodywin = newwin(DEFAULT_WIN_HEIGHT, DEFAULT_WIN_WIDTH, DEFAULT_WINDOW_START_ROW, DEFAULT_WINDOW_START_COL);
    assert(lui->bodywin != NULL);
    lui->formwin = derwin(lui->bodywin, FORM_WINDOW_HEIGHT, FORM_WINDOW_WIDTH, FORM_WINDOW_START_ROW, FORM_WINDOW_START_COL);
    assert(lui->formwin != NULL);
    //box(lui->formwin, 0, 0);
    //lui->menuwin = newwin(2, 12, MENU_ROW, 30);
    lui->menuwin = derwin(lui->bodywin, MENU_WINDOW_HEIGHT, MENU_WINDOW_WIDTH, MENU_WINDOW_START_ROW, MENU_WINDOW_START_COL);
    assert(lui->menuwin != NULL);
    //box(lui->menuwin, 0, 0);
    //lui->menuwin = newwin(2, 12, MENU_ROW, 30);
    lui->field = malloc(lui->numfields*sizeof(FIELD));
    assert(lui->field != NULL);
    /* Initialize the fields */
    //refresh();
    lui->field[0] = new_field(DEFAULT_FIELD_HEIGHT, INPUT_SIZE, USER_ROW, START_INPUT_COL, 0, 0);
    lui->field[1] = new_field(DEFAULT_FIELD_HEIGHT, INPUT_SIZE, PSWD_ROW, START_INPUT_COL, 0, 0);
    lui->field[2] = NULL;
    for (int i = 0; i < lui->numfields-1; i++)
        assert(lui->field[i] != NULL);

    /* Set field options */
    set_field_buffer(lui->field[0], 0, "uin");
    set_field_buffer(lui->field[1], 1, "pin");

    set_field_fore(lui->field[0], COLOR_PAIR(1));
    set_field_back(lui->field[1], COLOR_PAIR(2));

    set_field_opts(lui->field[0], O_VISIBLE | O_PUBLIC | O_EDIT | O_ACTIVE);
    set_field_opts(lui->field[1], O_VISIBLE | O_PUBLIC | O_EDIT | O_ACTIVE);

    set_field_back(lui->field[0], A_UNDERLINE);
    set_field_back(lui->field[1], A_UNDERLINE);

    /* Create the form and post it */
    lui->iform = new_form(lui->field);
    assert(lui->iform != NULL);
    set_form_win(lui->iform, lui->formwin);
    //tmpw1 = derwin(lui->formwin, 10, 40, USER_ROW-1, START_TEXT_COL-2);
    //box(tmpw1, 0, 0);
    //set_form_sub(lui->iform, tmpw1);
    set_form_sub(lui->iform, derwin(lui->formwin, FORM_SUBWIN_WIDTH, FORM_SUBWIN_HEIGHT, FORM_SUBWIN_START_ROW, FORM_SUBWIN_START_COL));
    post_form(lui->iform);
    //refresh();
    mvwprintw(lui->formwin, USER_ROW, START_TEXT_COL, "Login    :");
    mvwprintw(lui->formwin, PSWD_ROW, START_TEXT_COL, "Password :");
    
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
    menu_opts_on(lui->menu, O_ROWMAJOR);
    set_menu_win(lui->menu, lui->menuwin);
    set_menu_format(lui->menu, 1, 20);
    set_menu_mark(lui->menu, "");

    //set_current_field (lui->iform, lui->field[1]);
    //form_driver (lui->iform, REQ_CLR_FIELD);

    set_current_field (lui->iform, lui->field[0]);
    form_driver (lui->iform, REQ_CLR_FIELD);

    post_menu(lui->menu);
    //refresh();
    wrefresh(lui->bodywin);
    wrefresh(lui->formwin);
    wrefresh(lui->menuwin);

    return lui;
}

static char *trim_input(char *input)
{
     char *end;

     if (input == NULL)
        return NULL;

     while (isspace(*input))
        input++;

     if (*input == 0)
        return input;

     end = input + strnlen(input, 128) - 1;

     while (end > input && isspace(*end))
        end--;

     *(end+1) = '\0';

     return input;
}

int button_handle(login_ui_t *lui, ITEM *item)
{
     const char *name = item_name(item);

     if (strcmp(name, DONE_TEXT) == 0) {
        for (int i = 0; i < lui->numfields; i++) {
            if (!(field_opts(lui->field[i]) & O_ACTIVE))
                continue;

            //you can't read out the buffer of a field if the cursor is pointing on it.
            set_current_field (lui->iform, lui->field[0]);

            //printw("%s", field_buffer(lui->field[i], 0));
            printf("Read from buffer: }%s{\n",
                   trim_input(field_buffer(lui->field[i], 0)));
        } 
        sleep(10);
        return 1;
     } else if (strcmp(name, CANCEL_TEXT) == 0) {
        for (int i = 0; i < lui->numfields; i++) {
             set_current_field (lui->iform, lui->field[i]);
             form_driver (lui->iform, REQ_CLR_FIELD);
        }
     } else {
        exit(1);
     }
     return 0;
}


void run_login_loop(login_ui_t *lui)
{
    int ch, cy, cx;
    int stop = 0;
    int domenu = 0;

    keypad(lui->formwin, true);
    curs_set(1);
    cy = USER_ROW;
    cx = START_INPUT_COL;
    wmove(lui->formwin, cy, cx);
    wrefresh(lui->formwin);
    /* Loop through to get user requests */
    while (stop != 1 && (ch = wgetch(lui->formwin)) != KEY_ENTER)
    {
        //printf("Got ch: %x, UP is %x down %x\n", ch, KEY_UP, KEY_DOWN);
        if (domenu == 0) {
            switch(ch) {
            case KEY_DOWN:
                if (field_index(current_field(lui->iform)) == 1) {
                        domenu = 1;
                        break;
                }
                /* Go to next field */
                form_driver(lui->iform, REQ_NEXT_FIELD);
                /* Go to the end of the present buffer */
                /* Leaves nicely at the last character */
                form_driver(lui->iform, REQ_END_LINE);
                cy++;
                cy++;
                cx = START_INPUT_COL;
                break;
            case KEY_UP:
                /* Go to previous field */
                form_driver(lui->iform, REQ_PREV_FIELD);
                form_driver(lui->iform, REQ_END_LINE);
                cy++;
                cy++;
                cx = START_INPUT_COL;
                break;
            case KEY_BACKSPACE:
            case 127:
                form_driver(lui->iform, REQ_DEL_PREV);
                cx--;
                break;
            case KEY_DC:
                form_driver(lui->iform, REQ_DEL_CHAR);
                cx--;
                break;
            case KEY_LEFT:
                form_driver(lui->iform, REQ_PREV_CHAR);
                cx--;
                break;
            case KEY_RIGHT:
                form_driver(lui->iform, REQ_NEXT_CHAR);
                cx++;
                break;
            default:
                /* If this is a normal character, it gets */
                form_driver(lui->iform, ch);
                cx++;
                break;
            }
            wmove(lui->formwin, cy, cx);
            //refresh();
            //wrefresh(lui->formwin);
            //wrefresh(lui->menuwin);
        } else {
            switch(ch) {
            case KEY_UP:
                domenu = 0;
                break;
            case KEY_LEFT:
                menu_driver(lui->menu, REQ_LEFT_ITEM);
                break;
            case KEY_RIGHT:
                menu_driver(lui->menu, REQ_RIGHT_ITEM);
                break;
            case 10:
                if (button_handle(lui, current_item(lui->menu)) == 1) {
                     stop = 1;
                     break;
                }
            }
            //refresh();
            wrefresh(lui->bodywin);
            wrefresh(lui->menuwin);
        }

    }

}

int teardown_login_screen(login_ui_t *lui)
{
    /* Un post form and free the memory */
    unpost_form(lui->iform);
    free_form(lui->iform);

    for (int i = 0; i < lui->numfields; i++)
        free_field(lui->field[i]);

    for (int i = 0; i < lui->numitems; i++)
        free_item(lui->itms[i]);

    free_menu(lui->menu);

    delwin(lui->formwin);
    delwin(lui->menuwin);
    delwin(lui->bodywin);

    /* remove menus and also free lui */
    free(lui->itms);
    free(lui->field);
    free(lui);

    endwin();
    return 0;
}

/*int main()
{
    login_ui_t *lui;

    lui = setup_login_screen();
    run_login_loop(lui);
    teardown_login_screen(lui);
}*/


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

static void chown_tty(struct nlogin_context *cxt)
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
static void init_tty(struct nlogin_context *cxt)
{
	struct stat st;
	struct termios tt, ttt;
#define BAN_TTY "/dev/tty1"

        cxt->tty_path   = xmalloc(strlen(BAN_TTY));
	xstrncpy(cxt->tty_path, BAN_TTY, sizeof(BAN_TTY));
        cxt->tty_name   = cxt->tty_path + 3;
        cxt->tty_number = cxt->tty_path + 8; 

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
	//tcsetattr(0, TCSANOW, &ttt);

	/* open stdin,stdout,stderr to the tty */
        //	open_tty(cxt->tty_path);

	/* restore tty modes */
	tcsetattr(0, TCSAFLUSH, &tt);
}

static void log_lastlog(struct nlogin_context *cxt)
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

static void log_syslog(struct nlogin_context *cxt)
{
	struct passwd *pwd = cxt->pwd;

	if (!cxt->tty_name)
		return;

	if (!strncmp(cxt->tty_name, "ttyS", 4))
		syslog(LOG_INFO, _("Unsupported DIALUP AT %s BY %s"),
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
static void fork_session(void)
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
static void init_environ(struct nlogin_context *cxt)
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

	struct nlogin_context cxt = {
		.tty_mode = TTY_MODE,		  /* tty chmod() */
		.pid = getpid(),		  /* PID */
	};

	debug("inside login_now");
	signal(SIGQUIT, SIG_IGN);
	signal(SIGINT, SIG_IGN);

	setpriority(PRIO_PROCESS, 0, 0);
	//initproctitle(argc, argv);

	debug("setting username to root");
	cxt.username = xmalloc(10); /* XXX free, or better way to set it */
	memset(cxt.username, 0, 10);
	strcpy(cxt.username, "root");
	debug("set username to root");

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

	log_lastlog(&cxt);

	chown_tty(&cxt);

	if (setgid(pwd->pw_gid) < 0 && pwd->pw_gid) {
		syslog(LOG_ALERT, _("setgid() failed"));
		exit(EXIT_FAILURE);
	}

	if (pwd->pw_shell == NULL || *pwd->pw_shell == '\0')
		pwd->pw_shell = _PATH_BSHELL;

	init_environ(&cxt);		/* init $HOME, $TERM ... */

	//setproctitle(PRG_NAME, cxt.username);

	log_syslog(&cxt);

	motd();

	/*
	 * Detach the controlling terminal, fork, and create a new session
	 * and reinitialize syslog stuff.
	 */
	fork_session();
	debug("fork done\n");

	/* discard permissions last so we can't get killed and drop core */
	if (setuid(pwd->pw_uid) < 0 && pwd->pw_uid) {
		syslog(LOG_ALERT, _("setuid() failed"));
		exit(EXIT_FAILURE);
	}

	if (chdir(pwd->pw_dir) < 0) {
		warn(_("%s: change directory failed"), pwd->pw_dir);

		if (chdir("/"))
			warn(_("%s: change directory failed"), "/");
		pwd->pw_dir = "/";
		printf(_("Logging in with home = \"/\".\n"));
	}

        childArgc              = 0;
	childArgv[childArgc++] = "/bin/bash";
	childArgv[childArgc++] = "-sh";
	if ( argc > 1) {
		debug("handling argc\n");
                printf("%d arguments are {%s}-{%s}\n", argc, argv[0], argv[1]);
		buff = xmalloc(strlen(argv[1]) + 6);

		strcpy(buff, "exec ");
		strcat(buff, argv[1]);
		childArgv[childArgc++] = "-c";
		childArgv[childArgc++] = buff;
	}
    childArgv[childArgc++] = NULL;

	execvp(childArgv[0], childArgv + 1);

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

/* Parse command-line arguments. */
static void parse_args(int argc, char **argv, struct nlogin_context *op)
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


	debug("exiting parseargs\n");
}

/* Update our utmp entry. */
static void update_utmp(struct nlogin_context *op)
{
	struct utmpx ut;
	time_t t;
	pid_t pid = getpid();
	pid_t sid = getsid(0);
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

	while ((utp = getutxent()))
		if (utp->ut_pid == pid
				&& utp->ut_type >= INIT_PROCESS
				&& utp->ut_type <= DEAD_PROCESS)
			break;

	if (utp) {
		memcpy(&ut, utp, sizeof(ut));
	} else {
		char * ptr;

		/* Some inits do not initialize utmp. */
		memset(&ut, 0, sizeof(ut));
		size_t len = strlen(line);
		if (len >= sizeof(ut.ut_id))
			ptr = line + len - sizeof(ut.ut_id);
		else
			ptr = line;
		strncpy(ut.ut_id, ptr, sizeof(ut.ut_id));
	}

	strncpy(ut.ut_user, PRG_NAME, sizeof(ut.ut_user));
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

/* Set up tty as stdin, stdout & stderr. */
static void open_tty(char *tty, struct termios *tp, struct nlogin_context *op)
{
	const pid_t pid = getpid();
	int closed = 0;
        int serial;
        int fd;
	pid_t tid;
	gid_t gid = 0;
	struct stat st;

	/* Set up new standard input, unless we are given an already opened port. */
 
	/* Open the tty as standard input. */
	if ((fd = open(tty, O_RDWR|O_NOCTTY|O_NONBLOCK, 0)) < 0)
		log_err(_("/dev/%s: cannot open as standard input: %m"), tty);

	/*
	 * There is always a race between this reset and the call to
	 * vhangup() that s.o. can use to get access to your tty.
	 * Linux login(1) will change tty permissions. Use root owner and group
	 * with permission -rw------- for the period between getty and login.
	 */
	if (fchown(fd, 0, gid) || fchmod(fd, (gid ? 0620 : 0600))) {
		if (errno == EROFS)
			log_warn("%s: %m", tty);
		else
			log_err("%s: %m", tty);
	}

	/* Sanity checks... */
	if (fstat(fd, &st) < 0)
		log_err("%s: %m", tty);
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

	close(fd);

	debug("open(2)\n");
	if (open(tty, O_RDWR|O_NOCTTY|O_NONBLOCK, 0) != 0)
		log_err(_("/dev/%s: cannot open as standard input: %m"), tty);

	if (((tid = tcgetsid(STDIN_FILENO)) < 0) || (pid != tid)) {
		if (ioctl(STDIN_FILENO, TIOCSCTTY, 1) == -1)
			log_warn(_("/dev/%s: cannot get controlling tty: %m"), tty);
	}


	/*
	 * Standard input should already be connected to an open port. Make
	 * sure it is open for read/write.
	 */

	if ((fcntl(STDIN_FILENO, F_GETFL, 0) & O_RDWR) != O_RDWR)
		log_err(_("%s: not open for read/write"), tty);


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
	} else {
		log_err(_("%s: serial is not supported\n"), tty);
	}

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
static void termio_init(struct nlogin_context *op, struct termios *tp)
{
	if (op->flags & F_VCONSOLE) {
		setlocale(LC_CTYPE, "POSIX");
		//op->flags &= ~F_UTF8; VIJO -> FIXME
		reset_vc(op, tp);

		termio_clear(STDOUT_FILENO);
		return;
	}
        /* *ngetty is to be used only on vc */
	debug("term_io 2\n");
        log_err("This getty doesn't not support anything other than virtual consoles\n");
}

/* Reset virtual console on stdin to its defaults */
static void reset_vc(const struct nlogin_context *op, struct termios *tp)
{
	int fl = 0;

        debug("Resetting Virtual console(VC)..");
	fl |= (op->flags & F_KEEPCFLAGS) == 0 ? 0 : UL_TTY_KEEPCFLAGS;

	reset_virtual_console(tp, fl);

	if (tcsetattr(STDIN_FILENO, TCSADRAIN, tp))
		log_warn(_("setting terminal attributes failed: %m"));

	/* Go to blocking input even in local mode. */
	fcntl(STDIN_FILENO, F_SETFL,
		  fcntl(STDIN_FILENO, F_GETFL, 0) & ~O_NONBLOCK);
        debug("..completed");
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

	printf(USAGE_MAN_TAIL("bangetty(8)"));

	exit(EXIT_SUCCESS);
}

/*
 * Helper function reports errors to console or syslog.
 * Will be used by log_err() and log_warn() therefore
 * it takes a format as well as va_list.
 */
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
	struct nlogin_context options = {
		.tty    = "/dev/tty1"		/* default tty line */
	};
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
	update_utmp(&options);

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

	if (options.flags & F_VCONSOLE)
		/* Go to blocking mode unless -L is specified, this change
		 * affects stdout, stdin and stderr as all the file descriptors
		 * are created by dup().   */
		fcntl(STDOUT_FILENO, F_SETFL,
			  fcntl(STDOUT_FILENO, F_GETFL, 0) & ~O_NONBLOCK);

	INIT_CHARDATA(&chardata);

	sigaction(SIGQUIT, &sa_quit, NULL);
	sigaction(SIGINT, &sa_int, NULL);

	lui = setup_login_screen();
	run_login_loop(lui);
	teardown_login_screen(lui);
    debug("Tore down UI screen, next login_now()\n");

	/* Also updates utmp */
	login_now(argc, argv);
#ifdef DEBUGGING
	if (close_stream(dbf) != 0)
		log_err("write failed: %s", DEBUG_OUTPUT);
#endif
}
