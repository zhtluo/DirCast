#ifndef TOR_DIRVOTE_CON_H
#define TOR_DIRVOTE_CON_H

/** A vote networkstatus_t and its unparsed body: held around so we can
 * use it to generate a consensus (at voting_ends) and so we can serve it to
 * other authorities that might want it. */
typedef struct pending_vote_t {
  cached_dir_t *vote_body;
  networkstatus_t *vote;
} pending_vote_t;

/**
 * Structure for a cached vote.
 *
 */
struct cached_vote_t {
  cached_dir_t *vote_body;
  networkstatus_t *vote;
  char *auth_digest;
  smartlist_t *auth_confirmed;
  smartlist_t *auth_notified;
  /* Is the vote already added to the pending list? */
  int added;
  /* Is the notification already sent? */
  int sent;
};

int dirvote_upload_confirmation(void);
int dirvote_upload_notification(void);
int dirvote_cache_vote(const char *vote_body, const char **msg_out);
int dirvote_notify_vote(const char *vote_body, const char **msg_out); 
networkstatus_voter_info_t *get_voter(const networkstatus_t *vote);
void assert_any_sig_good(const networkstatus_voter_info_t *vi);
char *list_v3_auth_ids(void);
void add_new_cert_if_needed(const struct authority_cert_t *cert);
void dirvote_clear_cached_votes(void);
void dirvote_gather_commits(void);

extern smartlist_t *cached_vote_list;
#endif
