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

#ifdef USE_PLYMOUTH_SUPPORT
# include "plymouth-ctrl.h"
#endif

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

#include <security/pam_appl.h>
#ifdef HAVE_SECURITY_PAM_MISC_H
# include <security/pam_misc.h>
#elif defined(HAVE_SECURITY_OPENPAM_H)
# include <security/openpam.h>
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

/* Login prompt. */
#define LOGIN		"login: "
#define LOGIN_ARGV_MAX	16		/* Numbers of args for login */

/*
 * agetty --reload
 */
#ifdef AGETTY_RELOAD
# include <sys/inotify.h>
# include <linux/netlink.h>
# include <linux/rtnetlink.h>
# define AGETTY_RELOAD_FILENAME "/run/agetty.reload"	/* trigger file */
# define AGETTY_RELOAD_FDNONE	-2			/* uninitialized fd */
//static int inotify_fd = AGETTY_RELOAD_FDNONE;
//static int netlink_fd = AGETTY_RELOAD_FDNONE;
#endif

/*
 * When multiple baud rates are specified on the command line, the first one
 * we will try is the first one specified.
 */
#define	FIRST_SPEED	0

/* Storage for command-line options. */
#define	MAX_SPEED	10	/* max. nr. of baud rates */

struct options {
	int           flags;			/* toggle switches, see below */
	unsigned int  timeout;			/* time-out period */
	char         *tty;			    /* name of tty */
	char         *vcline;			/* line of virtual console */
	char         *term;	    		/* terminal type */
	char         *issue;			/* alternative issue file or directory */
	char         *osrelease;		/* /etc/os-release data */
	unsigned int  delay;			/* Sleep seconds before prompt */
	int           nice;			    /* Run login with this priority */
	int           numspeed;			/* number of baud rates to try */
	int           clocal;			/* CLOCAL_MODE_* */
	int           kbmode;			/* Keyboard mode if virtual console */
};

enum {
	CLOCAL_MODE_AUTO = 0,
	CLOCAL_MODE_ALWAYS,
	CLOCAL_MODE_NEVER
};


#define F_WAITCRLF	   (1<<5)	/* wait for CR or LF */
#define F_NOPROMPT	   (1<<7)	/* do not ask for login name! */
#define F_LCUC		   (1<<8)	/* support for *LCUC stty modes */
#define F_KEEPCFLAGS   (1<<10)	/* reuse c_cflags setup from kernel */
#define F_VCONSOLE	   (1<<12)	/* This is a virtual console */
#define F_HANGUP	   (1<<13)	/* Do call vhangup(2) */
#define F_UTF8		   (1<<14)	/* We can do UTF8 */
#define F_LOGINPAUSE   (1<<15)	/* Wait for any key before dropping login prompt */
#define F_NOCLEAR	   (1<<16)  /* Do not clear the screen before prompting */
#define F_NONL		   (1<<17)  /* No newline before issue */
#define F_NOHINTS	   (1<<20)  /* Don't print hints */

#define serial_tty_option(opt, flag)	\
	(((opt)->flags & (F_VCONSOLE|(flag))) == (flag))

static void parse_args(int argc, char **argv, struct options *op);
static void update_utmp(struct options *op);
static void open_tty(char *tty, struct termios *tp, struct options *op);
static void termio_init(struct options *op, struct termios *tp);
static void reset_vc (const struct options *op, struct termios *tp);
//static void do_prompt(struct options *op, struct termios *tp);
//static char *get_logname(struct options *op,
//			             struct termios *tp, struct chardata *cp);
static void termio_final(struct options *op,
			             struct termios *tp, struct chardata *cp);
//static int caps_lock(char *s);
static void usage(void) __attribute__((__noreturn__));
static void exit_slowly(int code) __attribute__((__noreturn__));
static void log_err(const char *, ...) __attribute__((__noreturn__))
			       __attribute__((__format__(printf, 1, 2)));
static void log_warn (const char *, ...)
				__attribute__((__format__(printf, 1, 2)));
//static ssize_t append(char *dest, size_t len, const char  *sep, const char *src);
static void check_username (const char* nm);
static void reload_agettys(void);
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

#define is_pam_failure(_rc)	((_rc) != PAM_SUCCESS)

#define LOGIN_MAX_TRIES        3
#define LOGIN_EXIT_TIMEOUT     5
#define LOGIN_TIMEOUT          60

#ifdef USE_TTY_GROUP
# define TTY_MODE 0620
#else
# define TTY_MODE 0600
#endif

#define	TTYGRPNAME	"tty"	/* name of group to own ttys */
#define VCS_PATH_MAX	64

/*
 * Login control struct
 */
struct login_context {
	const char	    *tty_path;	/* ttyname() return value */
	const char	    *tty_name;	/* tty_path without /dev prefix */
	const char	    *tty_number;	/* end of the tty_path */
	mode_t		     tty_mode;	/* chmod() mode */

	char		    *username;	/* from command line or PAM */
	struct passwd	*pwd;		/* user info */
	char		    *pwdbuf;	/* pwd strings */

	pam_handle_t	*pamh;		/* PAM handler */
	struct pam_conv	 conv;		/* PAM conversation */

#ifdef LOGIN_CHOWN_VCS
	char		     vcsn[VCS_PATH_MAX];	/* virtual console name */
	char		     vcsan[VCS_PATH_MAX];
#endif

	char		    *hostname;		/* remote machine */
	char		     hostaddress[16];	/* remote address */
	char		    *thishost;	/* this machine */
	char		    *thisdomain;/* this machine's domain */
	pid_t		     pid;
	int		         quiet;		/* 1 if hush file exists */
	int              noauth;
};

/*
 * This bounds the time given to login.  Not a define, so it can
 * be patched on machines where it's too small.
 */
static int child_pid = 0;
static volatile int got_sig = 0;

#ifdef LOGIN_CHOWN_VCS
/* true if the filedescriptor fd is a console tty, very Linux specific */
static int is_consoletty(int fd)
{
	struct stat stb;

	if ((fstat(fd, &stb) >= 0)
	    && (major(stb.st_rdev) == TTY_MAJOR)
	    && (minor(stb.st_rdev) < 64)) {
		return 1;
	}
	return 0;
}
#endif

#if 0
static char *xgethostname(void)
{
	char *name;
	size_t sz = get_hostname_max() + 1;

	name = malloc(sizeof(char) * sz);
	if (!name)
		log_err(_("failed to allocate memory: %m"));

	if (gethostname(name, sz) != 0) {
		free(name);
		return NULL;
	}
	name[sz - 1] = '\0';
	return name;
}
#endif


static void __attribute__ ((__noreturn__))
timedout2(int sig __attribute__ ((__unused__)))
{
	struct termios ti;

	/* reset echo */
	tcgetattr(0, &ti);
	ti.c_lflag |= ECHO;
	tcsetattr(0, TCSANOW, &ti);
	_exit(EXIT_SUCCESS);	/* %% */
}

static void timedout(int sig __attribute__ ((__unused__)))
{
	signal(SIGALRM, timedout2);
	alarm(10);
	//ignore_result( write(STDERR_FILENO, timeout_msg, strlen(timeout_msg)) );
	signal(SIGALRM, SIG_IGN);
	alarm(0);
	timedout2(0);
}

/*
 * This handler allows to inform a shell about signals to login. If you have
 * (root) permissions, you can kill all login children by one signal to the
 * login process.
 *
 * Also, a parent who is session leader is able (before setsid() in the child)
 * to inform the child when the controlling tty goes away (e.g. modem hangup).
 */
static void sig_handler(int signal)
{
	if (child_pid)
		kill(-child_pid, signal);
	else
		got_sig = 1;
	if (signal == SIGTERM)
		kill(-child_pid, SIGHUP);	/* because the shell often ignores SIGTERM */
}

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

static const char *get_thishost(struct login_context *cxt, const char **domain)
{
	if (!cxt->thishost) {
		cxt->thishost = xgethostname();
		if (!cxt->thishost) {
			if (domain)
				*domain = NULL;
			return NULL;
		}
		cxt->thisdomain = strchr(cxt->thishost, '.');
		if (cxt->thisdomain)
			*cxt->thisdomain++ = '\0';
	}

	if (domain)
		*domain = cxt->thisdomain;
	return cxt->thishost;
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

#if 0
/*
 * Nice and simple code provided by Linus Torvalds 16-Feb-93.
 * Non-blocking stuff by Maciej W. Rozycki, macro@ds2.pg.gda.pl, 1999.
 *
 * He writes: "Login performs open() on a tty in a blocking mode.
 * In some cases it may make login wait in open() for carrier infinitely,
 * for example if the line is a simplistic case of a three-wire serial
 * connection. I believe login should open the line in non-blocking mode,
 * leaving the decision to make a connection to getty (where it actually
 * belongs)."
 */
static void open_tty(const char *tty)
{
	int i, fd, flags;

	fd = open(tty, O_RDWR | O_NONBLOCK);
	if (fd == -1) {
		syslog(LOG_ERR, _("FATAL: can't reopen tty: %m"));
		sleepexit(EXIT_FAILURE);
	}

	if (!isatty(fd)) {
		close(fd);
		syslog(LOG_ERR, _("FATAL: %s is not a terminal"), tty);
		sleepexit(EXIT_FAILURE);
	}

	flags = fcntl(fd, F_GETFL);
	flags &= ~O_NONBLOCK;
	fcntl(fd, F_SETFL, flags);

	for (i = 0; i < fd; i++)
		close(i);
	for (i = 0; i < 3; i++)
		if (fd != i)
			dup2(fd, i);
	if (fd >= 3)
		close(fd);
}
#endif

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

#ifdef LOGIN_CHOWN_VCS
	if (is_consoletty(0)) {
		if (chown(cxt->vcsn, uid, gid))			/* vcs */
			chown_err(cxt->vcsn, uid, gid);
		if (chmod(cxt->vcsn, cxt->tty_mode))
			chmod_err(cxt->vcsn, cxt->tty_mode);

		if (chown(cxt->vcsan, uid, gid))		/* vcsa */
			chown_err(cxt->vcsan, uid, gid);
		if (chmod(cxt->vcsan, cxt->tty_mode))
			chmod_err(cxt->vcsan, cxt->tty_mode);
	}
#endif
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

#ifdef LOGIN_CHOWN_VCS
	if (cxt->tty_number) {
		/* find names of Virtual Console devices, for later mode change */
		snprintf(cxt->vcsn, sizeof(cxt->vcsn), "/dev/vcs%s", cxt->tty_number);
		snprintf(cxt->vcsan, sizeof(cxt->vcsan), "/dev/vcsa%s", cxt->tty_number);
	}
#endif

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


/*
 * Logs failed login attempts in _PATH_BTMP, if it exists.
 * Must be called only with username the name of an actual user.
 * The most common login failure is to give password instead of username.
 */
static void log_btmp(struct login_context *cxt)
{
	struct utmpx ut;
	struct timeval tv;

	memset(&ut, 0, sizeof(ut));

	strncpy(ut.ut_user,
		cxt->username ? cxt->username : "(unknown)",
		sizeof(ut.ut_user));

	if (cxt->tty_number)
		strncpy(ut.ut_id, cxt->tty_number, sizeof(ut.ut_id));
	if (cxt->tty_name)
		xstrncpy(ut.ut_line, cxt->tty_name, sizeof(ut.ut_line));

	gettimeofday(&tv, NULL);
	ut.ut_tv.tv_sec = tv.tv_sec;
	ut.ut_tv.tv_usec = tv.tv_usec;

	ut.ut_type = LOGIN_PROCESS;	/* XXX doesn't matter */
	ut.ut_pid = cxt->pid;

	if (cxt->hostname) {
		xstrncpy(ut.ut_host, cxt->hostname, sizeof(ut.ut_host));
		if (*cxt->hostaddress)
			memcpy(&ut.ut_addr_v6, cxt->hostaddress,
			       sizeof(ut.ut_addr_v6));
	}

	updwtmpx(_PATH_BTMP, &ut);
}


#ifdef HAVE_LIBAUDIT
static void log_audit(struct login_context *cxt, int status)
{
	int audit_fd;
	struct passwd *pwd = cxt->pwd;

	audit_fd = audit_open();
	if (audit_fd == -1)
		return;
	if (!pwd && cxt->username)
		pwd = getpwnam(cxt->username);

	audit_log_acct_message(audit_fd,
			       AUDIT_USER_LOGIN,
			       NULL,
			       "login",
			       cxt->username ? cxt->username : "(unknown)",
			       pwd ? pwd->pw_uid : (unsigned int) -1,
			       cxt->hostname,
			       NULL,
			       cxt->tty_name,
			       status);

	close(audit_fd);
}
#else				/* !HAVE_LIBAUDIT */
# define log_audit(cxt, status)
#endif				/* HAVE_LIBAUDIT */

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
	if (cxt->hostname)
		xstrncpy(ll.ll_host, cxt->hostname, sizeof(ll.ll_host));

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
	if (cxt->hostname) {
		xstrncpy(ut.ut_host, cxt->hostname, sizeof(ut.ut_host));
		if (*cxt->hostaddress)
			memcpy(&ut.ut_addr_v6, cxt->hostaddress,
			       sizeof(ut.ut_addr_v6));
	}

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
		if (cxt->hostname)
			syslog(LOG_NOTICE, _("ROOT LOGIN ON %s FROM %s"),
			       cxt->tty_name, cxt->hostname);
		else
			syslog(LOG_NOTICE, _("ROOT LOGIN ON %s"), cxt->tty_name);
	} else {
		if (cxt->hostname)
			syslog(LOG_INFO, _("LOGIN ON %s BY %s FROM %s"),
			       cxt->tty_name, pwd->pw_name, cxt->hostname);
		else
			syslog(LOG_INFO, _("LOGIN ON %s BY %s"), cxt->tty_name,
			       pwd->pw_name);
	}
}

/* encapsulate stupid "void **" pam_get_item() API */
static int loginpam_get_username(pam_handle_t *pamh, char **name)
{
	const void *item = (void *)*name;
	int rc;
	rc = pam_get_item(pamh, PAM_USER, &item);
	*name = (char *)item;
	return rc;
}

static void loginpam_err(pam_handle_t *pamh, int retcode)
{
	const char *msg = pam_strerror(pamh, retcode);

	if (msg) {
		fprintf(stderr, "\n%s\n", msg);
		syslog(LOG_ERR, "%s", msg);
	}
	pam_end(pamh, retcode);
	sleepexit(EXIT_FAILURE);
}

/*
 * Composes "<host> login: " string; or returns "login: " if -H is given or
 * LOGIN_PLAIN_PROMPT=yes configured.
 */
static const char *loginpam_get_prompt(struct login_context *cxt)
{
	const char *host;
	char *prompt, *dflt_prompt = _("login: ");
	size_t sz;

	if (!(host = get_thishost(cxt, NULL)))
		return dflt_prompt;

	sz = strlen(host) + 1 + strlen(dflt_prompt) + 1;
	prompt = xmalloc(sz);
	snprintf(prompt, sz, "%s %s", host, dflt_prompt);

	return prompt;
}

static pam_handle_t *init_loginpam(struct login_context *cxt)
{
	pam_handle_t *pamh = NULL;
	int rc;

	/*
	 * username is initialized to NULL and if specified on the command line
	 * it is set.  Therefore, we are safe not setting it to anything.
	 */
	rc = pam_start("login",
		       cxt->username, &cxt->conv, &pamh);
	if (rc != PAM_SUCCESS) {
		warnx(_("PAM failure, aborting: %s"), pam_strerror(pamh, rc));
		syslog(LOG_ERR, _("Couldn't initialize PAM: %s"),
		       pam_strerror(pamh, rc));
		sleepexit(EXIT_FAILURE);
	}

	/* hostname & tty are either set to NULL or their correct values,
	 * depending on how much we know. */
	rc = pam_set_item(pamh, PAM_RHOST, cxt->hostname);
	if (is_pam_failure(rc))
		loginpam_err(pamh, rc);

	rc = pam_set_item(pamh, PAM_TTY, cxt->tty_name);
	if (is_pam_failure(rc))
		loginpam_err(pamh, rc);

	/*
	 * Andrew.Taylor@cal.montage.ca: Provide a user prompt to PAM so that
	 * the "login: " prompt gets localized. Unfortunately, PAM doesn't have
	 * an interface to specify the "Password: " string (yet).
	 */
	rc = pam_set_item(pamh, PAM_USER_PROMPT, loginpam_get_prompt(cxt));
	if (is_pam_failure(rc))
		loginpam_err(pamh, rc);

	/* We don't need the original username. We have to follow PAM. */
	free(cxt->username);
	cxt->username = NULL;
	cxt->pamh = pamh;

	return pamh;
}

static void loginpam_auth(struct login_context *cxt)
{
	int rc;
    const char *retrystr;
	unsigned int retries, failcount = 0;
	const char *hostname = cxt->hostname ? cxt->hostname :
			       cxt->tty_name ? cxt->tty_name : "<unknown>";
	pam_handle_t *pamh = cxt->pamh;

	/* if we didn't get a user on the command line, set it to NULL */
	loginpam_get_username(pamh, &cxt->username);

	retrystr = getenv("LOGIN_RETRIES");
    retries  = atoi(retrystr);

	/*
	 * There may be better ways to deal with some of these conditions, but
	 * at least this way I don't think we'll be giving away information...
	 *
	 * Perhaps someday we can trust that all PAM modules will pay attention
	 * to failure count and get rid of LOGIN_MAX_TRIES?
	 */
	rc = pam_authenticate(pamh, 0);

	while ((++failcount < retries) &&
	       ((rc == PAM_AUTH_ERR) ||
		(rc == PAM_USER_UNKNOWN) ||
		(rc == PAM_CRED_INSUFFICIENT) ||
		(rc == PAM_AUTHINFO_UNAVAIL))) {

		/*if (rc == PAM_USER_UNKNOWN)
			cxt->username = NULL;
		else*/
			loginpam_get_username(pamh, &cxt->username);

		syslog(LOG_NOTICE,
		       _("FAILED LOGIN %u FROM %s FOR %s, %s"),
		       failcount, hostname,
		       cxt->username ? cxt->username : "(unknown)",
		       pam_strerror(pamh, rc));

		log_btmp(cxt);
		log_audit(cxt, 0);

		fprintf(stderr, _("Login incorrect\n\n"));

		pam_set_item(pamh, PAM_USER, NULL);
		rc = pam_authenticate(pamh, 0);
	}

	if (is_pam_failure(rc)) {

		/*if (rc == PAM_USER_UNKNOWN)
			cxt->username = NULL;
		else*/
			loginpam_get_username(pamh, &cxt->username);

		if (rc == PAM_MAXTRIES)
			syslog(LOG_NOTICE,
			       _("TOO MANY LOGIN TRIES (%u) FROM %s FOR %s, %s"),
			       failcount, hostname,
			       cxt->username ? cxt->username : "(unknown)",
			       pam_strerror(pamh, rc));
		else
			syslog(LOG_NOTICE,
			       _("FAILED LOGIN SESSION FROM %s FOR %s, %s"),
			       hostname,
			       cxt->username ? cxt->username : "(unknown)",
			       pam_strerror(pamh, rc));

		log_btmp(cxt);
		log_audit(cxt, 0);

		fprintf(stderr, _("\nLogin incorrect\n"));
		pam_end(pamh, rc);
		sleepexit(EXIT_SUCCESS);
	}
}

static void loginpam_acct(struct login_context *cxt)
{
	int rc;
	pam_handle_t *pamh = cxt->pamh;

	rc = pam_acct_mgmt(pamh, 0);

	if (rc == PAM_NEW_AUTHTOK_REQD)
		rc = pam_chauthtok(pamh, PAM_CHANGE_EXPIRED_AUTHTOK);

	if (is_pam_failure(rc))
		loginpam_err(pamh, rc);

	/*
	 * Grab the user information out of the password file for future use.
	 * First get the username that we are actually using, though.
	 */
	rc = loginpam_get_username(pamh, &cxt->username);
	if (is_pam_failure(rc))
		loginpam_err(pamh, rc);

	if (!cxt->username || !*cxt->username) {
		warnx(_("\nSession setup problem, abort."));
		syslog(LOG_ERR, _("NULL user name in %s:%d. Abort."),
		       __FUNCTION__, __LINE__);
		pam_end(pamh, PAM_SYSTEM_ERR);
		sleepexit(EXIT_FAILURE);
	}
}

/*
 * Note that the position of the pam_setcred() call is discussable:
 *
 *  - the PAM docs recommend pam_setcred() before pam_open_session()
 *  - but the original RFC http://www.opengroup.org/rfc/mirror-rfc/rfc86.0.txt
 *    uses pam_setcred() after pam_open_session()
 *
 * The old login versions (before year 2011) followed the RFC. This is probably
 * not optimal, because there could be a dependence between some session modules
 * and the user's credentials.
 *
 * The best is probably to follow openssh and call pam_setcred() before and
 * after pam_open_session().                -- kzak@redhat.com (18-Nov-2011)
 *
 */
static void loginpam_session(struct login_context *cxt)
{
	int rc;
	pam_handle_t *pamh = cxt->pamh;

	rc = pam_setcred(pamh, PAM_ESTABLISH_CRED);
	if (is_pam_failure(rc))
		loginpam_err(pamh, rc);

	rc = pam_open_session(pamh, 0);
	if (is_pam_failure(rc)) {
		pam_setcred(cxt->pamh, PAM_DELETE_CRED);
		loginpam_err(pamh, rc);
	}

	rc = pam_setcred(pamh, PAM_REINITIALIZE_CRED);
	if (is_pam_failure(rc)) {
		pam_close_session(pamh, 0);
		loginpam_err(pamh, rc);
	}
}

/*
 * Detach the controlling terminal, fork, restore syslog stuff, and create
 * a new session.
 */
static void fork_session(struct login_context *cxt)
{
	struct sigaction sa, oldsa_hup, oldsa_term;

	signal(SIGALRM, SIG_DFL);
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

	/*
	 * We have to beware of SIGTERM, because leaving a PAM session
	 * without pam_close_session() is a pretty bad thing.
	 */
	sa.sa_handler = sig_handler;
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGTERM, &sa, &oldsa_term);

	closelog();

	/*
	 * We must fork before setuid(), because we need to call
	 * pam_close_session() as root.
	 */
	child_pid = fork();
	if (child_pid < 0) {
		warn(_("fork failed"));

		pam_setcred(cxt->pamh, PAM_DELETE_CRED);
		pam_end(cxt->pamh, pam_close_session(cxt->pamh, 0));
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
		openlog("login", LOG_ODELAY, LOG_AUTHPRIV);

		pam_setcred(cxt->pamh, PAM_DELETE_CRED);
		pam_end(cxt->pamh, pam_close_session(cxt->pamh, 0));
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
	openlog("login", LOG_ODELAY, LOG_AUTHPRIV);	/* reopen */

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
	char *termenv, **env;
	char tmp[PATH_MAX];
	int len, i;

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

	/* mailx will give a funny error msg if you forget this one */
	len = snprintf(tmp, sizeof(tmp), "%s/%s", _PATH_MAILDIR, pwd->pw_name);
	if (len > 0 && (size_t) len < sizeof(tmp))
		xsetenv("MAIL", tmp, 0);

	/* LOGNAME is not documented in login(1) but HP-UX 6.5 does it. We'll
	 * not allow modifying it.
	 */
	xsetenv("LOGNAME", pwd->pw_name, 1);

	env = pam_getenvlist(cxt->pamh);
	for (i = 0; env && env[i]; i++)
		putenv(env[i]);
}


void login_now(int argc, char **argv)
{
	int cnt;
	char *childArgv[10];
	char *buff;
	int childArgc = 0;
	int retcode;
	struct sigaction act;
	struct passwd *pwd;

	struct login_context cxt = {
		.tty_mode = TTY_MODE,		  /* tty chmod() */
		.pid = getpid(),		  /* PID */
#ifdef HAVE_SECURITY_PAM_MISC_H
		.conv = { misc_conv, NULL }	  /* Linux-PAM conversation function */
#elif defined(HAVE_SECURITY_OPENPAM_H)
		.conv = { openpam_ttyconv, NULL } /* OpenPAM conversation function */
#endif

	};

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	signal(SIGALRM, timedout);
	(void) sigaction(SIGALRM, NULL, &act);
	act.sa_flags &= ~SA_RESTART;
	sigaction(SIGALRM, &act, NULL);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGINT, SIG_IGN);

	setpriority(PRIO_PROCESS, 0, 0);
	initproctitle(argc, argv);

	if (*argv) {
		char *p = *argv;
		cxt.username = xstrdup(p);

		/* Wipe the name - some people mistype their password here. */
		/* (Of course we are too late, but perhaps this helps a little...) */
		while (*p)
			*p++ = ' ';
	}

	for (cnt = get_fd_tabsize() - 1; cnt > 2; cnt--)
		close(cnt);

	setpgrp();	 /* set pgid to pid this means that setsid() will fail */
	init_tty(&cxt);

	openlog("login", LOG_ODELAY, LOG_AUTHPRIV);

	init_loginpam(&cxt);

	/* the user has already been authenticated */
	cxt.noauth = getuid() == 0 ? 1 : 0;

	if (!cxt.noauth)
		loginpam_auth(&cxt);

	/*
	 * Authentication may be skipped (for example, during krlogin, rlogin,
	 * etc...), but it doesn't mean that we can skip other account checks.
	 * The account could be disabled or the password has expired (although
	 * the kerberos ticket is valid).      -- kzak@redhat.com (22-Feb-2006)
	 */
	loginpam_acct(&cxt);

	cxt.pwd = xgetpwnam(cxt.username, &cxt.pwdbuf);
	if (!cxt.pwd) {
		warnx(_("\nSession setup problem, abort."));
		syslog(LOG_ERR, _("Invalid user name \"%s\" in %s:%d. Abort."),
		       cxt.username, __FUNCTION__, __LINE__);
		pam_end(cxt.pamh, PAM_SYSTEM_ERR);
		sleepexit(EXIT_FAILURE);
	}

	pwd = cxt.pwd;
	cxt.username = pwd->pw_name;

	/*
	 * Initialize the supplementary group list. This should be done before
	 * pam_setcred, because PAM modules might add groups during that call.
	 *
	 * For root we don't call initgroups, instead we call setgroups with
	 * group 0. This avoids the need to step through the whole group file,
	 * which can cause problems if NIS, NIS+, LDAP or something similar
	 * is used and the machine has network problems.
	 */
	retcode = pwd->pw_uid ? initgroups(cxt.username, pwd->pw_gid) :	/* user */
			        setgroups(0, NULL);			/* root */
	if (retcode < 0) {
		syslog(LOG_ERR, _("groups initialization failed: %m"));
		warnx(_("\nSession setup problem, abort."));
		pam_end(cxt.pamh, PAM_SYSTEM_ERR);
		sleepexit(EXIT_FAILURE);
	}

	/*
	 * Open PAM session (after successful authentication and account check).
	 */
	loginpam_session(&cxt);

	/* committed to login -- turn off timeout */
	alarm((unsigned int)0);

	endpwent();

	cxt.quiet = 0;//get_hushlogin_status(pwd, 1);

	log_utmp(&cxt);
	log_audit(&cxt, 1);
	log_lastlog(&cxt);

	chown_tty(&cxt);

	if (setgid(pwd->pw_gid) < 0 && pwd->pw_gid) {
		syslog(LOG_ALERT, _("setgid() failed"));
		exit(EXIT_FAILURE);
	}

	if (pwd->pw_shell == NULL || *pwd->pw_shell == '\0')
		pwd->pw_shell = _PATH_BSHELL;

	init_environ(&cxt);		/* init $HOME, $TERM ... */

	setproctitle("login", cxt.username);

	log_syslog(&cxt);

	if (!cxt.quiet) {
		motd();
//yes
#ifdef LOGIN_STAT_MAIL
		/*
		 * This turns out to be a bad idea: when the mail spool
		 * is NFS mounted, and the NFS connection hangs, the
		 * login hangs, even root cannot login.
		 * Checking for mail should be done from the shell.
		 */
		{
			struct stat st;
			char *mail;

			mail = getenv("MAIL");
			if (mail && stat(mail, &st) == 0 && st.st_size != 0) {
				if (st.st_mtime > st.st_atime)
					printf(_("You have new mail.\n"));
				else
					printf(_("You have mail.\n"));
			}
		}
#endif
	}

	/*
	 * Detach the controlling terminal, fork, and create a new session
	 * and reinitialize syslog stuff.
	 */
	fork_session(&cxt);

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
		RELOAD_OPTION,
	};
	const struct option longopts[] = {
		{  "init-string",    required_argument,  NULL,  'I'  },
		{  "reload",         no_argument,        NULL,  RELOAD_OPTION },
		{  "version",	     no_argument,	     NULL,  VERSION_OPTION  },
		{  "help",	         no_argument,	     NULL,  HELP_OPTION     },
		{ NULL, 0, NULL, 0 }
	};

	while ((c = getopt_long(argc, argv,
			   "8a:cC:d:Ef:hH:iI:Jl:L::mnNo:pP:r:Rst:Uw", longopts,
			    NULL)) != -1) {
		switch (c) {
		case 'L':
			/* -L and -L=always have the same meaning */
			op->clocal = CLOCAL_MODE_ALWAYS;
			if (optarg) {
				if (strcmp(optarg, "=always") == 0)
					op->clocal = CLOCAL_MODE_ALWAYS;
				else if (strcmp(optarg, "=never") == 0)
					op->clocal = CLOCAL_MODE_NEVER;
				else if (strcmp(optarg, "=auto") == 0)
					op->clocal = CLOCAL_MODE_AUTO;
				else
					log_err(_("invalid argument of --local-line"));
			}
			break;
		case 'P':
			op->nice = strtos32_or_err(optarg,  _("invalid nice argument"));
			break;
		case 't':
			op->timeout = strtou32_or_err(optarg,  _("invalid timeout argument"));
			break;
		case 'U':
			op->flags |= F_LCUC;
			break;
		case RELOAD_OPTION:
			reload_agettys();
			exit(EXIT_SUCCESS);
		case VERSION_OPTION:
			output_version();
			exit(EXIT_SUCCESS);
		case HELP_OPTION:
			usage();
		default:
			errtryhelp(EXIT_FAILURE);
		}
	}

	debug("after getopt loop\n");

#if 0
	if (argc < optind + 1) {
		log_warn(_("not enough arguments"));
		errx(EXIT_FAILURE, _("not enough arguments"));
	}
#endif

	/* On virtual console remember the line which is used for */
	if (strncmp(op->tty, "tty", 3) == 0 &&
	    strspn(op->tty + 3, "0123456789") == strlen(op->tty+3))
		op->vcline = op->tty+3;

#if 0
	if (argc > optind && argv[optind])
		op->term = argv[optind];
#endif
        op->term = 0; /* XXX hardcoded to 0 for now, Vijo */

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
#ifndef KDGKBMODE
	int serial;
#endif

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

	/*
	 * The following ioctl will fail if stdin is not a tty, but also when
	 * there is noise on the modem control lines. In the latter case, the
	 * common course of action is (1) fix your cables (2) give the modem
	 * more time to properly reset after hanging up.
	 *
	 * SunOS users can achieve (2) by patching the SunOS kernel variable
	 * "zsadtrlow" to a larger value; 5 seconds seems to be a good value.
	 * http://www.sunmanagers.org/archives/1993/0574.html
	 */
	memset(tp, 0, sizeof(struct termios));
	if (tcgetattr(STDIN_FILENO, tp) < 0)
		log_err(_("%s: failed to get terminal attributes: %m"), tty);


	/*
	 * Detect if this is a virtual console or serial/modem line.
	 * In case of a virtual console the ioctl KDGKBMODE succeeds
	 * whereas on other lines it will fails.
	 */
#ifdef KDGKBMODE
	if (ioctl(STDIN_FILENO, KDGKBMODE, &op->kbmode) == 0)
#else
	if (ioctl(STDIN_FILENO, TIOCMGET, &serial) < 0 && (errno == EINVAL))
#endif
	{
		op->flags |= F_VCONSOLE;
		if (!op->term)
			op->term = DEFAULT_VCTERM;
	} else {
#ifdef K_RAW
		op->kbmode = K_RAW;
#endif
		if (!op->term)
			op->term = DEFAULT_STERM;
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
#ifdef USE_PLYMOUTH_SUPPORT
	struct termios lock;
	int i =  (plymouth_command(MAGIC_PING) == 0) ? PLYMOUTH_TERMIOS_FLAGS_DELAY : 0;
	if (i)
		plymouth_command(MAGIC_QUIT);
	while (i-- > 0) {
		/*
		 * Even with TTYReset=no it seems with systemd or plymouth
		 * the termios flags become changed from under the first
		 * agetty on a serial system console as the flags are locked.
		 */
		memset(&lock, 0, sizeof(struct termios));
		if (ioctl(STDIN_FILENO, TIOCGLCKTRMIOS, &lock) < 0)
			break;
		if (!lock.c_iflag && !lock.c_oflag && !lock.c_cflag && !lock.c_lflag)
			break;
		debug("termios locked\n");
		sleep(1);
	}
	memset(&lock, 0, sizeof(struct termios));
	ioctl(STDIN_FILENO, TIOCSLCKTRMIOS, &lock);
#endif

	if (op->flags & F_VCONSOLE) {
#if defined(IUTF8) && defined(KDGKBMODE)
		switch(op->kbmode) {
		case K_UNICODE:
			setlocale(LC_CTYPE, "C.UTF-8");
			op->flags |= F_UTF8;
			break;
		case K_RAW:
		case K_MEDIUMRAW:
		case K_XLATE:
		default:
			setlocale(LC_CTYPE, "POSIX");
			op->flags &= ~F_UTF8;
			break;
		}
#else
		setlocale(LC_CTYPE, "POSIX");
		op->flags &= ~F_UTF8;
#endif
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

#ifdef IUTF8
	tp->c_iflag = tp->c_iflag & IUTF8;
	if (tp->c_iflag & IUTF8)
		op->flags |= F_UTF8;
#else
	tp->c_iflag = 0;
#endif
	tp->c_lflag = 0;
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
	fl |= (op->flags & F_UTF8)       == 0 ? 0 : UL_TTY_UTF8;

	reset_virtual_console(tp, fl);

	if (tcsetattr(STDIN_FILENO, TCSADRAIN, tp))
		log_warn(_("setting terminal attributes failed: %m"));

	/* Go to blocking input even in local mode. */
	fcntl(STDIN_FILENO, F_SETFL,
	      fcntl(STDIN_FILENO, F_GETFL, 0) & ~O_NONBLOCK);
}

#ifdef AGETTY_RELOAD
#if 0
static void open_netlink(void)
{
	struct sockaddr_nl addr = { 0, };
	int sock;

	if (netlink_fd != AGETTY_RELOAD_FDNONE)
		return;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock >= 0) {
		addr.nl_family = AF_NETLINK;
		addr.nl_pid = getpid();
		addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
		if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
			close(sock);
		else
			netlink_fd = sock;
	}
}

static int process_netlink_msg(int *changed)
{
	char buf[4096];
	struct sockaddr_nl snl;
	struct nlmsghdr *h;
	int rc;

	struct iovec iov = {
		.iov_base = buf,
		.iov_len = sizeof(buf)
	};
	struct msghdr msg = {
		.msg_name = &snl,
		.msg_namelen = sizeof(snl),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0
	};

	rc = recvmsg(netlink_fd, &msg, MSG_DONTWAIT);
	if (rc < 0) {
		if (errno == EWOULDBLOCK || errno == EAGAIN)
			return 0;

		/* Failure, just stop listening for changes */
		close(netlink_fd);
		netlink_fd = AGETTY_RELOAD_FDNONE;
		return 0;
	}

	for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned int)rc); h = NLMSG_NEXT(h, rc)) {
		if (h->nlmsg_type == NLMSG_DONE ||
		    h->nlmsg_type == NLMSG_ERROR) {
			close(netlink_fd);
			netlink_fd = AGETTY_RELOAD_FDNONE;
			return 0;
		}

		*changed = 1;
		break;
	}

	return 1;
}

static int process_netlink(void)
{
	int changed = 0;
	while (process_netlink_msg(&changed));
	return changed;
}
#endif

#if 0
static int wait_for_term_input(int fd)
{
	char buffer[sizeof(struct inotify_event) + NAME_MAX + 1];
	fd_set rfds;

	if (inotify_fd == AGETTY_RELOAD_FDNONE) {
		/* make sure the reload trigger file exists */
		int reload_fd = open(AGETTY_RELOAD_FILENAME,
					O_CREAT|O_CLOEXEC|O_RDONLY,
					S_IRUSR|S_IWUSR);

		/* initialize reload trigger inotify stuff */
		if (reload_fd >= 0) {
			inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
			if (inotify_fd > 0)
				inotify_add_watch(inotify_fd, AGETTY_RELOAD_FILENAME,
					  IN_ATTRIB | IN_MODIFY);

			close(reload_fd);
		} else
			log_warn(_("failed to create reload file: %s: %m"),
					AGETTY_RELOAD_FILENAME);
	}

	while (1) {
		int nfds = fd;

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);

		if (inotify_fd >= 0) {
			FD_SET(inotify_fd, &rfds);
			nfds = max(nfds, inotify_fd);
		}
		if (netlink_fd >= 0) {
			FD_SET(netlink_fd, &rfds);
			nfds = max(nfds, netlink_fd);
		}

		/* If waiting fails, just fall through, presumably reading input will fail */
		if (select(nfds + 1, &rfds, NULL, NULL, NULL) < 0)
			return 1;

		if (FD_ISSET(fd, &rfds)) {
			return 1;

		} else if (netlink_fd >= 0 && FD_ISSET(netlink_fd, &rfds)) {
			if (!process_netlink())
				continue;

		/* Just drain the inotify buffer */
		} else if (inotify_fd >= 0 && FD_ISSET(inotify_fd, &rfds)) {
			while (read(inotify_fd, buffer, sizeof (buffer)) > 0);
		}

		return 0;
	}
}
#endif  /* AGETTY_RELOAD */
#endif

static void print_issue_file(struct options *op, struct termios *tp __attribute__((__unused__)))
{
    (void)op;
	/* Issue not in use, start with a new line. */
	write_all(STDOUT_FILENO, "\r\n", 2);
}

#if 0
/* Show login prompt, optionally preceded by /etc/issue contents. */
static void do_prompt(struct options *op, struct termios *tp)
{
#ifdef AGETTY_RELOAD
again:
#endif
	print_issue_file(op, tp);

#ifdef KDGKBLED
	if ((op->flags & F_VCONSOLE)) {
		int kb = 0;

		if (ioctl(STDIN_FILENO, KDGKBLED, &kb) == 0) {
			char hint[256] = { '\0' };
			int nl = 0;

			if (access(_PATH_NUMLOCK_ON, F_OK) == 0)
				nl = 1;

			if (nl && (kb & 0x02) == 0)
				append(hint, sizeof(hint), NULL, _("Num Lock off"));

			else if (nl == 0 && (kb & 2) && (kb & 0x20) == 0)
				append(hint, sizeof(hint), NULL, _("Num Lock on"));

			if ((kb & 0x04) && (kb & 0x40) == 0)
				append(hint, sizeof(hint), ", ", _("Caps Lock on"));

			if ((kb & 0x01) && (kb & 0x10) == 0)
				append(hint, sizeof(hint), ", ",  _("Scroll Lock on"));

			if (*hint)
				printf(_("Hint: %s\n\n"), hint);
		}
	}
#endif /* KDGKBLED */
		char *hn = xgethostname();

		if (hn) {
			char *dot = strchr(hn, '.');
			char *cn = hn;
			struct addrinfo *res = NULL;

				if (dot)
					*dot = '\0';

			if (dot == NULL) {
				struct addrinfo hints;

				memset(&hints, 0, sizeof(hints));
				hints.ai_flags = AI_CANONNAME;

				if (!getaddrinfo(hn, NULL, &hints, &res)
				    && res && res->ai_canonname)
					cn = res->ai_canonname;
			}

			write_all(STDOUT_FILENO, cn, strlen(cn));
			write_all(STDOUT_FILENO, " ", 1);

			if (res)
				freeaddrinfo(res);
			free(hn);
		}

		/* Always show login prompt. */
		write_all(STDOUT_FILENO, LOGIN, sizeof(LOGIN) - 1);
}
#endif

#if 0
/* Get user name, establish parity, speed, erase, kill & eol. */
static char *get_logname(struct options *op, struct termios *tp, struct chardata *cp)
{
	static char logname[BUFSIZ];
	char *bp;
	char c;			/* input character, full eight bits */
	char ascval;		/* low 7 bits of input character */
	int eightbit;
	//static char *erase[] = {	/* backspace-space-backspace */
	//	"\010\040\010",		/* space parity */
	//	"\010\040\010",		/* odd parity */
	//	"\210\240\210",		/* even parity */
	//	"\210\240\210",		/* no parity */
	//};

	/* Initialize kill, erase, parity etc. (also after switching speeds). */
	INIT_CHARDATA(cp);

	/*
	 * Flush pending input (especially important after parsing or switching
	 * the baud rate).
	 */
	if ((op->flags & F_VCONSOLE) == 0)
		sleep(1);
	tcflush(STDIN_FILENO, TCIFLUSH);

	bp = logname;
	*bp = '\0';

	while (*logname == '\0') {
		/* Write issue file and prompt */
		do_prompt(op, tp);

#ifdef AGETTY_RELOAD
		if (!wait_for_term_input(STDIN_FILENO)) {
			/* refresh prompt -- discard input data, clear terminal
			 * and call do_prompt() again
			 */
			if ((op->flags & F_VCONSOLE) == 0)
				sleep(1);
			tcflush(STDIN_FILENO, TCIFLUSH);
			if (op->flags & F_VCONSOLE)
				termio_clear(STDOUT_FILENO);
			bp = logname;
			*bp = '\0';
			continue;
		}
#endif
		cp->eol = '\0';

		/* Read name, watch for break and end-of-line. */
		while (cp->eol == '\0') {

			ssize_t readres;

			debug("read from FD\n");
			readres = read(STDIN_FILENO, &c, 1);
			if (readres < 0) {
				debug("read failed\n");

				/* The terminal could be open with O_NONBLOCK when
				 * -L (force CLOCAL) is specified...  */
				if (errno == EINTR || errno == EAGAIN) {
					xusleep(250000);
					continue;
				}
				switch (errno) {
				case 0:
				case EIO:
				case ESRCH:
				case EINVAL:
				case ENOENT:
					exit_slowly(EXIT_SUCCESS);
				default:
					log_err(_("%s: read: %m"), op->tty);
				}
			}

			if (readres == 0)
				c = 0;

			/* Do parity bit handling. */
			if (eightbit)
				ascval = c;
			else if (c != (ascval = (c & 0177))) {
				uint32_t bits;			/* # of "1" bits per character */
				uint32_t mask;			/* mask with 1 bit up */
				for (bits = 1, mask = 1; mask & 0177; mask <<= 1) {
					if (mask & ascval)
						bits++;
				}
				cp->parity |= ((bits & 1) ? 1 : 2);
			}
		}
	}

	if ((op->flags & F_LCUC) && (cp->capslock = caps_lock(logname))) {

		/* Handle names with upper case and no lower case. */
		for (bp = logname; *bp; bp++)
			if (isupper(*bp))
				*bp = tolower(*bp);		/* map name to lower case */
	}

	return logname;
}
#endif

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

#if 0
/*
 * String contains upper case without lower case.
 * http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=52940
 * http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=156242
 */
static int caps_lock(char *s)
{
	int capslock;

	for (capslock = 0; *s; s++) {
		if (islower(*s))
			return EXIT_SUCCESS;
		if (capslock == 0)
			capslock = isupper(*s);
	}
	return capslock;
}
#endif

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

#if 0
static void dolog(const char *fmt, va_list ap)
{
	int fd;
	char buf[BUFSIZ];
	char *bp;

	/*
	 * If the diagnostic is reported via syslog(3), the process name is
	 * automatically prepended to the message. If we write directly to
	 * /dev/console, we must prepend the process name ourselves.
	 */
	str2cpy(buf, program_invocation_short_name, ": ");
	bp = buf + strlen(buf);
	vsnprintf(bp, sizeof(buf)-strlen(buf), fmt, ap);

	/* Terminate with CR-LF since the console mode is unknown. */
	strcat(bp, "\r\n");
	if ((fd = open("/dev/console", 1)) >= 0) {
		write_all(fd, buf, strlen(buf));
		close(fd);
	}
}
#endif

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

#if 0
static void print_addr(sa_family_t family, void *addr)
{
	char buff[INET6_ADDRSTRLEN + 1];

	inet_ntop(family, addr, buff, sizeof(buff));
	printf("%s", buff);
}

/*
 * Appends @str to @dest and if @dest is not empty then use @sep as a
 * separator. The maximal final length of the @dest is @len.
 *
 * Returns the final @dest length or -1 in case of error.
 */
static ssize_t append(char *dest, size_t len, const char  *sep, const char *src)
{
	size_t dsz = 0, ssz = 0, sz;
	char *p;

	if (!dest || !len || !src)
		return -1;

	if (*dest)
		dsz = strlen(dest);
	if (dsz && sep)
		ssz = strlen(sep);
	sz = strlen(src);

	if (dsz + ssz + sz + 1 > len)
		return -1;

	p = dest + dsz;
	if (ssz) {
		memcpy(p, sep, ssz);
		p += ssz;
	}
	memcpy(p, src, sz);
	*(p + sz) = '\0';

	return dsz + ssz + sz;
}
#endif

/*
 * Do not allow the user to pass an option as a user name
 * To be more safe: Use `--' to make sure the rest is
 * interpreted as non-options by the program, if it supports it.
 */
static void check_username(const char* nm)
{
	const char *p = nm;
	if (!nm)
		goto err;
	if (strlen(nm) > 42)
		goto err;
	while (isspace(*p))
		p++;
	if (*p == '-')
		goto err;
	return;
err:
	errno = EPERM;
	log_err(_("checkname failed: %m"));
}

static void reload_agettys(void)
{
#ifdef AGETTY_RELOAD
	int fd = open(AGETTY_RELOAD_FILENAME, O_CREAT|O_CLOEXEC|O_WRONLY,
					      S_IRUSR|S_IWUSR);
	if (fd < 0)
		err(EXIT_FAILURE, _("cannot open %s"), AGETTY_RELOAD_FILENAME);

	if (futimens(fd, NULL) < 0 || close(fd) < 0)
		err(EXIT_FAILURE, _("cannot touch file %s"),
		    AGETTY_RELOAD_FILENAME);
#else
	/* very unusual */
	errx(EXIT_FAILURE, _("--reload is unsupported on your system"));
#endif
}

int main(int argc, char **argv)
{
	char *username = NULL;			/* login name, given to /bin/login */
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

	/* Update the utmp file. */
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

	/* Set the optional timer. */
	if (options.timeout)
		alarm(options.timeout);

	/* Optionally wait for CR or LF before writing /etc/issue */
	if (serial_tty_option(&options, F_WAITCRLF)) {
		char ch;

		debug("waiting for cr-lf\n");
		while (read(STDIN_FILENO, &ch, 1) == 1) {
			/* Strip "parity bit". */
			ch &= 0x7f;
#ifdef DEBUGGING
			fprintf(dbf, "read %c\n", ch);
#endif
			if (ch == '\n' || ch == '\r')
				break;
		}
	}

	INIT_CHARDATA(&chardata);

	print_issue_file(&options, &termios);

	/* Disable timer. */
	if (options.timeout)
		alarm(0);

	if ((options.flags & F_VCONSOLE) == 0) {
		/* Finalize the termios settings. */
		termio_final(&options, &termios, &chardata);

		/* Now the newline character should be properly written. */
		write_all(STDOUT_FILENO, "\r\n", 2);
	}

	sigaction(SIGQUIT, &sa_quit, NULL);
	sigaction(SIGINT, &sa_int, NULL);

	if (username)
		check_username(username);

	//login_argv[login_argc] = NULL;	/* last login argv */

	if (options.nice && nice(options.nice) < 0)
		log_warn(_("%s: can't change process priority: %m"),
			 options.tty);

	free(options.osrelease);
#ifdef DEBUGGING
	if (close_stream(dbf) != 0)
		log_err("write failed: %s", DEBUG_OUTPUT);
#endif

	/* Let the login program take care of password validation. */
	//execv(options.login, login_argv);
	//log_err(_("%s: can't exec %s: %m"), options.tty, login_argv[0]);

    lui = setup_login_screen();
    run_login_loop(lui);
    teardown_login_screen(lui);

    login_now(argc, argv);
}
