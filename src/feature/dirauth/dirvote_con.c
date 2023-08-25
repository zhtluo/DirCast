#include "app/config/config.h"
#include "app/config/resolve_addr.h"
#include "core/or/or.h"
#include "core/or/policies.h"
#include "core/or/protover.h"
#include "core/or/tor_version_st.h"
#include "core/or/versions.h"
#include "feature/client/entrynodes.h" /* needed for guardfraction methods */
#include "feature/dirauth/authmode.h"
#include "feature/dirauth/bwauth.h"
#include "feature/dirauth/dirauth_options_st.h"
#include "feature/dirauth/dirauth_sys.h"
#include "feature/dirauth/dircollate.h"
#include "feature/dirauth/dsigs_parse.h"
#include "feature/dirauth/guardfraction.h"
#include "feature/dirauth/ns_detached_signatures_st.h"
#include "feature/dirauth/recommend_pkg.h"
#include "feature/dirauth/shared_random_state.h"
#include "feature/dirauth/vote_microdesc_hash_st.h"
#include "feature/dirauth/voteflags.h"
#include "feature/dirauth/voting_schedule.h"
#include "feature/dircache/cached_dir_st.h"
#include "feature/dircache/dirserv.h"
#include "feature/dirclient/dir_server_st.h"
#include "feature/dirclient/dirclient.h"
#include "feature/dircommon/directory.h"
#include "feature/dircommon/vote_timing_st.h"
#include "feature/dirparse/microdesc_parse.h"
#include "feature/dirparse/ns_parse.h"
#include "feature/dirparse/parsecommon.h"
#include "feature/dirparse/signing.h"
#include "feature/nodelist/authcert.h"
#include "feature/nodelist/authority_cert_st.h"
#include "feature/nodelist/dirlist.h"
#include "feature/nodelist/document_signature_st.h"
#include "feature/nodelist/fmt_routerstatus.h"
#include "feature/nodelist/microdesc.h"
#include "feature/nodelist/microdesc_st.h"
#include "feature/nodelist/networkstatus.h"
#include "feature/nodelist/networkstatus_st.h"
#include "feature/nodelist/networkstatus_voter_info_st.h"
#include "feature/nodelist/node_st.h"
#include "feature/nodelist/nodefamily.h"
#include "feature/nodelist/nodelist.h"
#include "feature/nodelist/routerinfo_st.h"
#include "feature/nodelist/routerlist.h"
#include "feature/nodelist/routerlist_st.h"
#include "feature/nodelist/torcert.h"
#include "feature/nodelist/vote_routerstatus_st.h"
#include "feature/relay/router.h"
#include "feature/relay/routerkeys.h"
#include "feature/stats/rephist.h"
#include "lib/container/order.h"
#include "lib/crypt_ops/crypto_format.h"
#include "lib/encoding/confline.h"

/* Our header */

#include "feature/dirauth/dirvote_con.h"

/** All cached votes.
 */
smartlist_t *cached_vote_list = NULL;

/** Given a vote <b>vote</b> (not a consensus!), return its associated
 * networkstatus_voter_info_t. */
networkstatus_voter_info_t *get_voter(const networkstatus_t *vote) {
  tor_assert(vote);
  tor_assert(vote->type == NS_TYPE_VOTE);
  tor_assert(vote->voters);
  /* Now we have confirmation and the length may not be 1. */
  /* tor_assert(smartlist_len(vote->voters) == 1); */
  return smartlist_get(vote->voters, 0);
}

/* Check the voter information <b>vi</b>, and assert that at least one
 * signature is good. Asserts on failure. */
void assert_any_sig_good(const networkstatus_voter_info_t *vi) {
  int any_sig_good = 0;
  SMARTLIST_FOREACH(vi->sigs, document_signature_t *, sig,
                    if (sig->good_signature) any_sig_good = 1);
  tor_assert(any_sig_good);
}

/** Return a newly allocated string containing the hex-encoded v3 authority
    identity digest of every recognized v3 authority. */
char *list_v3_auth_ids(void) {
  smartlist_t *known_v3_keys = smartlist_new();
  char *keys;
  SMARTLIST_FOREACH(router_get_trusted_dir_servers(), dir_server_t *, ds,
                    if ((ds->type & V3_DIRINFO) &&
                        !tor_digest_is_zero(ds->v3_identity_digest))
                        smartlist_add(known_v3_keys,
                                      tor_strdup(hex_str(ds->v3_identity_digest,
                                                         DIGEST_LEN))));
  keys = smartlist_join_strings(known_v3_keys, ", ", 0, NULL);
  SMARTLIST_FOREACH(known_v3_keys, char *, cp, tor_free(cp));
  smartlist_free(known_v3_keys);
  return keys;
}

/* Add <b>cert</b> to our list of known authority certificates. */
void add_new_cert_if_needed(const struct authority_cert_t *cert) {
  tor_assert(cert);
  if (!authority_cert_get_by_digests(cert->cache_info.identity_digest,
                                     cert->signing_key_digest)) {
    /* Hey, it's a new cert! */
    trusted_dirs_load_certs_from_string(cert->cache_info.signed_descriptor_body,
                                        TRUSTED_DIRS_CERTS_SRC_FROM_VOTE,
                                        1 /*flush*/, NULL);
    if (!authority_cert_get_by_digests(cert->cache_info.identity_digest,
                                       cert->signing_key_digest)) {
      log_warn(LD_BUG, "We added a cert, but still couldn't find it.");
    }
  }
}

static networkstatus_voter_info_t *dirserv_generate_voter_info(
    crypto_pk_t *private_key, authority_cert_t *cert) {
  const or_options_t *options = get_options();
  tor_addr_t addr;
  char *hostname = NULL;
  const char *contact;
  char identity_digest[DIGEST_LEN];
  char signing_key_digest[DIGEST_LEN];
  networkstatus_voter_info_t *voter = NULL;

  tor_assert(private_key);
  tor_assert(cert);

  if (crypto_pk_get_digest(private_key, signing_key_digest) < 0) {
    log_err(LD_BUG, "Error computing signing key digest");
    return NULL;
  }
  if (crypto_pk_get_digest(cert->identity_key, identity_digest) < 0) {
    log_err(LD_BUG, "Error computing identity key digest");
    return NULL;
  }
  if (!find_my_address(options, AF_INET, LOG_WARN, &addr, NULL, &hostname)) {
    log_warn(LD_NET, "Couldn't resolve my hostname");
    return NULL;
  }
  if (!hostname || !strchr(hostname, '.')) {
    tor_free(hostname);
    hostname = tor_addr_to_str_dup(&addr);
  }

  if (!hostname) {
    log_err(LD_BUG, "Failed to determine hostname AND duplicate address");
    return NULL;
  }

  contact = tor_strdup(get_options()->ContactInfo);
  if (!contact) contact = tor_strdup("(none)");

  voter = tor_malloc_zero(sizeof(networkstatus_voter_info_t));
  voter->nickname = tor_strdup(options->Nickname);
  memcpy(voter->identity_digest, identity_digest, DIGEST_LEN);
  voter->sigs = smartlist_new();
  voter->address = hostname;
  tor_addr_copy(&voter->ipv4_addr, &addr);
  voter->ipv4_dirport = routerconf_find_dir_port(options, 0);
  voter->ipv4_orport = routerconf_find_or_port(options, AF_INET);
  voter->contact = tor_strdup(contact);
  return voter;
}

static void voter_info_free(networkstatus_voter_info_t *voter) {
  tor_free(voter->nickname);
  tor_free(voter->address);
  tor_free(voter->contact);
  if (voter->sigs) {
    SMARTLIST_FOREACH(voter->sigs, document_signature_t *, sig,
                      document_signature_free(sig));
    smartlist_free(voter->sigs);
  }
  tor_free(voter);
}

/**
 * Upload one vote we know about to everyone.
 *
 */
static int dirvote_upload_one_confirmation(struct cached_vote_t *v) {
  crypto_pk_t *key = get_my_v3_authority_signing_key();
  authority_cert_t *cert = get_my_v3_authority_cert();
  time_t now = time(NULL);
  char fingerprint[FINGERPRINT_LEN + 1];

  char *vote_text;

  if (!cert || !key) {
    log_warn(LD_NET, "Didn't find key/certificate to generate v3 confirmation");
    return -1;
  } else if (cert->expires < now) {
    log_warn(LD_NET, "Can't generate v3 confirmation with expired certificate");
    return -1;
  }

  base16_encode(fingerprint, sizeof(fingerprint),
                cert->cache_info.identity_digest, DIGEST_LEN);

  networkstatus_voter_info_t *voter = dirserv_generate_voter_info(key, cert);
  const char *ip_str = fmt_addr(&voter->ipv4_addr);

  {
    /* Add our signature. */
    char *vote = tor_malloc_zero(v->vote_body->dir_len + 1);
    smartlist_t *new_vote = smartlist_new();
    memcpy(vote, v->vote_body->dir, v->vote_body->dir_len + 1);
    smartlist_add(new_vote, vote);
    smartlist_add_asprintf(new_vote,
                           "dir-source %s %s %s %s %d %d\n"
                           "contact %s\n",
                           voter->nickname, fingerprint, voter->address, ip_str,
                           voter->ipv4_dirport, voter->ipv4_orport,
                           voter->contact);
    {
      char signing_key_fingerprint[FINGERPRINT_LEN + 1];
      if (crypto_pk_get_fingerprint(key, signing_key_fingerprint, 0) < 0) {
        log_warn(LD_BUG, "Unable to get fingerprint for signing key");
        goto err;
      }
      smartlist_add_asprintf(new_vote, "directory-signature %s %s\n",
                             fingerprint, signing_key_fingerprint);
    }
    {
      char *sig = router_get_dirobj_signature(v->vote_body->digests.d[0],
                                              DIGEST_LEN, key);
      if (!sig) {
        log_warn(LD_BUG, "Unable to sign networkstatus vote.");
        goto err;
      }
      smartlist_add(new_vote, sig);
    }
    vote_text = smartlist_join_strings(new_vote, "", 0, NULL);
    directory_post_to_dirservers(DIR_PURPOSE_UPLOAD_VOTE,
                                 ROUTER_PURPOSE_GENERAL, V3_DIRINFO, vote_text,
                                 strlen(vote_text), 0);
    log_notice(LD_DIR, "Confirmation for %s posted.",
               get_voter(v->vote)->nickname);
  err:
    tor_free(vote);
    smartlist_free(new_vote);
  }
  voter_info_free(voter);
  return 0;
}

/**
 * Upload all votes we know about to everyone.
 *
 */
int dirvote_upload_confirmation(void) {
  crypto_pk_t *key = get_my_v3_authority_signing_key();
  authority_cert_t *cert = get_my_v3_authority_cert();
  time_t now = time(NULL);
  char fingerprint[FINGERPRINT_LEN + 1];

  char *vote_text;

  if (!cert || !key) {
    log_warn(LD_NET, "Didn't find key/certificate to generate v3 confirmation");
    return -1;
  } else if (cert->expires < now) {
    log_warn(LD_NET, "Can't generate v3 confirmation with expired certificate");
    return -1;
  }

  base16_encode(fingerprint, sizeof(fingerprint),
                cert->cache_info.identity_digest, DIGEST_LEN);

  networkstatus_voter_info_t *voter = dirserv_generate_voter_info(key, cert);
  const char *ip_str = fmt_addr(&voter->ipv4_addr);

  if (!cached_vote_list) {
    return 0;
  }

  SMARTLIST_FOREACH_BEGIN(cached_vote_list, struct cached_vote_t *, v) {
    /* Add our signature. */
    char *vote = tor_malloc_zero(v->vote_body->dir_len + 1);
    smartlist_t *new_vote = smartlist_new();
    memcpy(vote, v->vote_body->dir, v->vote_body->dir_len + 1);
    smartlist_add(new_vote, vote);
    smartlist_add_asprintf(new_vote,
                           "dir-source %s %s %s %s %d %d\n"
                           "contact %s\n",
                           voter->nickname, fingerprint, voter->address, ip_str,
                           voter->ipv4_dirport, voter->ipv4_orport,
                           voter->contact);
    {
      char signing_key_fingerprint[FINGERPRINT_LEN + 1];
      if (crypto_pk_get_fingerprint(key, signing_key_fingerprint, 0) < 0) {
        log_warn(LD_BUG, "Unable to get fingerprint for signing key");
        goto err;
      }
      smartlist_add_asprintf(new_vote, "directory-signature %s %s\n",
                             fingerprint, signing_key_fingerprint);
    }
    {
      char *sig = router_get_dirobj_signature(v->vote_body->digests.d[0],
                                              DIGEST_LEN, key);
      if (!sig) {
        log_warn(LD_BUG, "Unable to sign networkstatus vote.");
        goto err;
      }
      smartlist_add(new_vote, sig);
    }
    vote_text = smartlist_join_strings(new_vote, "", 0, NULL);
    directory_post_to_dirservers(DIR_PURPOSE_UPLOAD_VOTE,
                                 ROUTER_PURPOSE_GENERAL, V3_DIRINFO, vote_text,
                                 strlen(vote_text), 0);
    log_notice(LD_DIR, "Confirmation for %s posted.",
               get_voter(v->vote)->nickname);
  err:
    tor_free(vote);
    smartlist_free(new_vote);
  }
  SMARTLIST_FOREACH_END(v);
  voter_info_free(voter);
  return 0;
}

/**
 * Form and upload msgs to everyone.
 *
 */
int dirvote_upload_notification(void) {
  crypto_pk_t *key = get_my_v3_authority_signing_key();
  authority_cert_t *cert = get_my_v3_authority_cert();
  time_t now = time(NULL);
  char fingerprint[FINGERPRINT_LEN + 1];

  char *vote_text;

  if (!cert || !key) {
    log_warn(LD_NET, "Didn't find key/certificate to generate v3 confirmation");
    return -1;
  } else if (cert->expires < now) {
    log_warn(LD_NET, "Can't generate v3 confirmation with expired certificate");
    return -1;
  }

  base16_encode(fingerprint, sizeof(fingerprint),
                cert->cache_info.identity_digest, DIGEST_LEN);

  networkstatus_voter_info_t *voter = dirserv_generate_voter_info(key, cert);
  const char *ip_str = fmt_addr(&voter->ipv4_addr);

  if (!cached_vote_list) {
    return 0;
  }

  SMARTLIST_FOREACH_BEGIN(cached_vote_list, struct cached_vote_t *, v) {
    if (v->sent == 0) {
      /* Add our signature. */
      char *vote = tor_malloc_zero(v->vote_body->dir_len + 1);
      smartlist_t *new_vote = smartlist_new();
      memcpy(vote, v->vote_body->dir, v->vote_body->dir_len + 1);
      smartlist_add(new_vote, vote);
      smartlist_add_asprintf(new_vote,
                             "network-msg notify\n"
                             "dir-source %s %s %s %s %d %d\n"
                             "contact %s\n",
                             voter->nickname, fingerprint, voter->address,
                             ip_str, voter->ipv4_dirport, voter->ipv4_orport,
                             voter->contact);
      {
        char signing_key_fingerprint[FINGERPRINT_LEN + 1];
        if (crypto_pk_get_fingerprint(key, signing_key_fingerprint, 0) < 0) {
          log_warn(LD_BUG, "Unable to get fingerprint for signing key");
          goto err;
        }
        smartlist_add_asprintf(new_vote, "directory-signature %s %s\n",
                               fingerprint, signing_key_fingerprint);
      }
      {
        char *sig = router_get_dirobj_signature(v->vote_body->digests.d[0],
                                                DIGEST_LEN, key);
        if (!sig) {
          log_warn(LD_BUG, "Unable to sign networkstatus vote.");
          goto err;
        }
        smartlist_add(new_vote, sig);
      }
      vote_text = smartlist_join_strings(new_vote, "", 0, NULL);
      directory_post_to_dirservers(DIR_PURPOSE_UPLOAD_VOTE,
                                   ROUTER_PURPOSE_GENERAL, V3_DIRINFO,
                                   vote_text, strlen(vote_text), 0);
      log_notice(LD_DIR, "Notification for %s posted.",
                 get_voter(v->vote)->nickname);
      v->sent = 1;
    err:
      tor_free(vote);
      smartlist_free(new_vote);
    }
  }
  SMARTLIST_FOREACH_END(v);
  voter_info_free(voter);
  return 0;
}

/** Cache a vote for confirmation.
 */
int dirvote_cache_vote(const char *vote_body, const char **msg_out) {
  networkstatus_t *vote;
  const char *end_of_vote = NULL;
  networkstatus_voter_info_t *vi;
  dir_server_t *ds;
  vote = networkstatus_parse_vote_from_string(vote_body, strlen(vote_body),
                                              &end_of_vote, NS_TYPE_VOTE);

  if (!end_of_vote) end_of_vote = vote_body + strlen(vote_body);
  if (!vote) {
    log_warn(LD_DIR, "Couldn't parse vote: length was %d",
             (int)strlen(vote_body));
    *msg_out = "Unable to parse vote";
    goto err;
  }
  vi = get_voter(vote);
  assert_any_sig_good(vi);
  ds = trusteddirserver_get_by_v3_auth_digest(vi->identity_digest);
  if (!ds) {
    char *keys = list_v3_auth_ids();
    log_warn(LD_DIR,
             "Got a vote from an authority (nickname %s, address %s) "
             "with authority key ID %s. "
             "This key ID is not recognized.  Known v3 key IDs are: %s",
             vi->nickname, vi->address,
             hex_str(vi->identity_digest, DIGEST_LEN), keys);
    tor_free(keys);
    *msg_out = "Vote not from a recognized v3 authority";
    goto err;
  }
  add_new_cert_if_needed(vote->cert);

  /* Is it for the right period? */
  if (vote->valid_after != voting_schedule.interval_starts) {
    char tbuf1[ISO_TIME_LEN + 1], tbuf2[ISO_TIME_LEN + 1];
    format_iso_time(tbuf1, vote->valid_after);
    format_iso_time(tbuf2, voting_schedule.interval_starts);
    log_warn(LD_DIR,
             "Rejecting vote from %s with valid-after time of %s; "
             "we were expecting %s",
             vi->address, tbuf1, tbuf2);
    *msg_out = "Bad valid-after time";
    goto err;
  }

  if (!cached_vote_list) {
    cached_vote_list = smartlist_new();
  }

  struct cached_vote_t *vote_in_cache;
  int found_vote = 0;
  SMARTLIST_FOREACH_BEGIN(cached_vote_list, struct cached_vote_t *, v) {
    if (tor_memeq(v->vote->digests.d[0], vi->vote_digest, DIGEST_LEN)) {
      /* TODO: make sure that the votes are equal */
      found_vote = 1;
      vote_in_cache = v;
      break;
    }
  }
  SMARTLIST_FOREACH_END(v);
  if (!found_vote) {
    /* Add the vote to the cache */
    log_notice(LD_DIR, "Adding vote of %s to the cache",
               get_voter(vote)->nickname);
    struct cached_vote_t *c_vote = tor_malloc(sizeof(struct cached_vote_t));
    c_vote->auth_digest = tor_malloc(20);
    memcpy(c_vote->auth_digest, vi->identity_digest, 20);
    c_vote->vote = vote;
    c_vote->vote_body = new_cached_dir(
        tor_strndup(vote_body, end_of_vote - vote_body), vote->published);
    c_vote->auth_confirmed = smartlist_new();
    c_vote->auth_notified = smartlist_new();
    c_vote->added = 0;
    c_vote->sent = 0;
    smartlist_add(cached_vote_list, c_vote);
    vote_in_cache = c_vote;
  }
  SMARTLIST_FOREACH_BEGIN(vote->voters, networkstatus_voter_info_t *, voter) {
    int found_sig = 0;
    SMARTLIST_FOREACH_BEGIN(vote_in_cache->auth_confirmed, char *, au) {
      if (tor_memeq(au, voter->identity_digest, DIGEST_LEN)) {
        found_sig = 1;
        break;
      }
    }
    SMARTLIST_FOREACH_END(au);
    if (!found_sig) {
      log_notice(LD_DIR,
                 "Adding signature of %s for the vote of %s to the cache, "
                 "totaling %d signature(s).",
                 voter->nickname, get_voter(vote)->nickname,
                 smartlist_len(vote_in_cache->auth_confirmed) + 1);
      char *digest = tor_malloc(20);
      memcpy(digest, voter->identity_digest, DIGEST_LEN);
      smartlist_add(vote_in_cache->auth_confirmed, digest);
    }
  }
  SMARTLIST_FOREACH_END(voter);
  if (found_vote) {
    networkstatus_vote_free(vote);
  } else {
    dirvote_upload_one_confirmation(vote_in_cache);
  }
  /*
  int n_v3_authorities = get_n_authorities(V3_DIRINFO);
  int n_required = n_v3_authorities / 2 + 1;
  if (!vote_in_cache->added &&
      smartlist_len(vote_in_cache->auth_confirmed) >= n_required) {
    log_notice(LD_DIR,
               "Adding the vote of %s for signatures reaching the quorum.",
               get_voter(vote_in_cache->vote)->nickname);
    vote_in_cache->added = 1;
    return 1;
  }
  */
  return 0;

err:
  return -1;
}

/** Handles a notify message.
 */
int dirvote_notify_vote(const char *vote_body, const char **msg_out) {
  networkstatus_t *vote;
  const char *end_of_vote = NULL;
  networkstatus_voter_info_t *vi;
  dir_server_t *ds;
  smartlist_t *a_vote = smartlist_new();

  vote = networkstatus_parse_msg_from_string(
      vote_body, strlen(vote_body), &end_of_vote, NS_TYPE_VOTE, a_vote);

  if (!end_of_vote) end_of_vote = vote_body + strlen(vote_body);
  if (!vote) {
    log_warn(LD_DIR, "Couldn't parse vote: length was %d",
             (int)strlen(vote_body));
    *msg_out = "Unable to parse vote";
    goto err;
  }
  vi = get_voter(vote);
  assert_any_sig_good(vi);
  ds = trusteddirserver_get_by_v3_auth_digest(vi->identity_digest);
  if (!ds) {
    char *keys = list_v3_auth_ids();
    log_warn(LD_DIR,
             "Got a vote from an authority (nickname %s, address %s) "
             "with authority key ID %s. "
             "This key ID is not recognized.  Known v3 key IDs are: %s",
             vi->nickname, vi->address,
             hex_str(vi->identity_digest, DIGEST_LEN), keys);
    tor_free(keys);
    *msg_out = "Vote not from a recognized v3 authority";
    goto err;
  }
  add_new_cert_if_needed(vote->cert);

  /* Is it for the right period? */
  if (vote->valid_after != voting_schedule.interval_starts) {
    char tbuf1[ISO_TIME_LEN + 1], tbuf2[ISO_TIME_LEN + 1];
    format_iso_time(tbuf1, vote->valid_after);
    format_iso_time(tbuf2, voting_schedule.interval_starts);
    log_warn(LD_DIR,
             "Rejecting vote from %s with valid-after time of %s; "
             "we were expecting %s",
             vi->address, tbuf1, tbuf2);
    *msg_out = "Bad valid-after time";
    goto err;
  }

  if (!cached_vote_list) {
    cached_vote_list = smartlist_new();
  }

  struct cached_vote_t *vote_in_cache;
  int found_vote = 0;
  SMARTLIST_FOREACH_BEGIN(cached_vote_list, struct cached_vote_t *, v) {
    if (tor_memeq(v->vote->digests.d[0], vi->vote_digest, DIGEST_LEN)) {
      /* TODO: make sure that the votes are equal */
      found_vote = 1;
      vote_in_cache = v;
      break;
    }
  }
  SMARTLIST_FOREACH_END(v);
  if (!found_vote) {
    /* Add the vote to the cache */
    log_notice(LD_DIR, "Adding vote of %s to the cache",
               get_voter(vote)->nickname);
    struct cached_vote_t *c_vote = tor_malloc(sizeof(struct cached_vote_t));
    c_vote->auth_digest = tor_malloc(20);
    memcpy(c_vote->auth_digest, vi->identity_digest, 20);
    c_vote->vote = vote;
    c_vote->vote_body = new_cached_dir(
        tor_strndup(vote_body, end_of_vote - vote_body), vote->published);
    c_vote->auth_confirmed = smartlist_new();
    c_vote->auth_notified = smartlist_new();
    c_vote->added = 0;
    c_vote->sent = 0;
    smartlist_add(cached_vote_list, c_vote);
    vote_in_cache = c_vote;
  }
  SMARTLIST_FOREACH_BEGIN(vote->voters, networkstatus_voter_info_t *, voter) {
    int found_sig = 0;
    SMARTLIST_FOREACH_BEGIN(vote_in_cache->auth_confirmed, char *, au) {
      if (tor_memeq(au, voter->identity_digest, DIGEST_LEN)) {
        found_sig = 1;
        break;
      }
    }
    SMARTLIST_FOREACH_END(au);
    if (!found_sig) {
      log_notice(LD_DIR,
                 "Adding signature of %s for the vote of %s to the cache, "
                 "totaling %d signature(s).",
                 voter->nickname, get_voter(vote)->nickname,
                 smartlist_len(vote_in_cache->auth_confirmed) + 1);
      char *digest = tor_malloc(20);
      memcpy(digest, voter->identity_digest, DIGEST_LEN);
      smartlist_add(vote_in_cache->auth_confirmed, digest);
    }
  }
  SMARTLIST_FOREACH_END(voter);
  SMARTLIST_FOREACH_BEGIN(a_vote, networkstatus_voter_info_t *, voter) {
    int found_sig = 0;
    SMARTLIST_FOREACH_BEGIN(vote_in_cache->auth_notified, char *, au) {
      if (tor_memeq(au, voter->identity_digest, DIGEST_LEN)) {
        found_sig = 1;
        break;
      }
    }
    SMARTLIST_FOREACH_END(au);
    if (!found_sig) {
      log_notice(LD_DIR,
                 "Adding signature of %s for the msg of %s to the cache, "
                 "totaling %d signature(s).",
                 voter->nickname, get_voter(vote)->nickname,
                 smartlist_len(vote_in_cache->auth_notified) + 1);
      char *digest = tor_malloc(20);
      memcpy(digest, voter->identity_digest, DIGEST_LEN);
      smartlist_add(vote_in_cache->auth_notified, digest);
    }
  }
  SMARTLIST_FOREACH_END(voter);
  int n_v3_authorities = get_n_authorities(V3_DIRINFO);
  int n_required = n_v3_authorities / 2 + 1;
  if (!vote_in_cache->added &&
      smartlist_len(vote_in_cache->auth_notified) >= n_required) {
    int count = 0;
    SMARTLIST_FOREACH(cached_vote_list, struct cached_vote_t *, cv, {
      count += (strcmp(smartlist_get(cv->auth_confirmed, 0),
                       smartlist_get(vote_in_cache->auth_confirmed, 0))
                    ? 0
                    : 1);
    });
    if (count > 1) {
      log_warn(LD_DIR, "Detecting equivocation in the vote of %s.",
               get_voter(vote_in_cache->vote)->nickname);
      smartlist_free(a_vote);
      return 0;
    }
    log_notice(LD_DIR,
               "Adding the vote of %s for signatures reaching the quorum.",
               get_voter(vote_in_cache->vote)->nickname);
    vote_in_cache->added = 1;
    smartlist_free(a_vote);
    dirvote_upload_notification();
    return 1;
  }
  smartlist_free(a_vote);
  if (found_vote) {
    networkstatus_vote_free(vote);
  }
  return 0;

err:
  smartlist_free(a_vote);
  return -1;
}

void dirvote_clear_cached_votes(void) {
  if (!cached_vote_list) cached_vote_list = smartlist_new();

  SMARTLIST_FOREACH(cached_vote_list, struct cached_vote_t *, v, {
    tor_free(v->auth_digest);
    networkstatus_vote_free(v->vote);
    tor_free(v->vote_body);
    SMARTLIST_FOREACH(v->auth_confirmed, char *, au, { tor_free(au); });
    smartlist_free(v->auth_confirmed);
    SMARTLIST_FOREACH(v->auth_notified, char *, au, { tor_free(au); });
    smartlist_free(v->auth_notified);
    tor_free(v);
  });
  smartlist_clear(cached_vote_list);
}
