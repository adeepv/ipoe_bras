//-----------------------------------------------------------------------------
#include "term.h"
//-----------------------------------------------------------------------------
void term_set_user_active(struct term_session *ts) {
	/* �������� �������� ��� ��������� */
	if (!(ts->st.flags & TERM_SES_ONLINE)) {
		ts->st.flags |= TERM_SES_ONLINE;

		/* �������� ������ �������� � �������. */
		term_add_work(ts);

		/* ����� ��������� ����� ���������. */
		ts->st.lastChgState = jiffies;

	}
	/* ����� ��������� ���������� */
	ts->st.lastOnline = jiffies;
}
//-----------------------------------------------------------------------------
void term_set_user_inactive(struct term_session *ts) {
	/* �������� �������� ��� �� ��������� */
	if (ts->st.flags & TERM_SES_ONLINE) {
		ts->st.flags &= ~TERM_SES_ONLINE;

		/* �������� ������ �������� � �������. */
		term_add_work(ts);

		/* ����� ��������� ����� ���������. */
		ts->st.lastChgState = jiffies;

	}
}
//-----------------------------------------------------------------------------
