//-----------------------------------------------------------------------------
#include "term.h"
//-----------------------------------------------------------------------------
void term_set_user_active(struct term_session *ts) {
	/* Помечаем абонента как активного */
	if (!(ts->st.flags & TERM_SES_ONLINE)) {
		ts->st.flags |= TERM_SES_ONLINE;

		/* Помещаем нижнюю половину в очередь. */
		term_add_work(ts);

		/* Время последней смены состояния. */
		ts->st.lastChgState = jiffies;

	}
	/* Время последней активности */
	ts->st.lastOnline = jiffies;
}
//-----------------------------------------------------------------------------
void term_set_user_inactive(struct term_session *ts) {
	/* Помечаем абонента как не активного */
	if (ts->st.flags & TERM_SES_ONLINE) {
		ts->st.flags &= ~TERM_SES_ONLINE;

		/* Помещаем нижнюю половину в очередь. */
		term_add_work(ts);

		/* Время последней смены состояния. */
		ts->st.lastChgState = jiffies;

	}
}
//-----------------------------------------------------------------------------
