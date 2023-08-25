#include "feature/dirauth/dirvote_con.h"

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

/** Send an HTTP Request to every authority for every vote.
 */
static void dirvote_fetch_all_votes(void) {
  smartlist_t *fps = smartlist_new();
  char *resource;

  SMARTLIST_FOREACH_BEGIN(router_get_trusted_dir_servers(), dir_server_t *,
                          ds) {
    if (!(ds->type & V3_DIRINFO)) continue;
    char *cp = tor_malloc(HEX_DIGEST_LEN + 1);
    base16_encode(cp, HEX_DIGEST_LEN + 1, ds->v3_identity_digest, DIGEST_LEN);
    smartlist_add(fps, cp);
  }
  SMARTLIST_FOREACH_END(ds);

  if (!smartlist_len(fps)) {
    smartlist_free(fps);
    return;
  }
  {
    char *tmp = smartlist_join_strings(fps, " ", 0, NULL);
    log_notice(LOG_NOTICE,
               "Asking every other authorities (%s) for a copy of the vote.",
               smartlist_len(fps), tmp);
    tor_free(tmp);
  }
  resource = smartlist_join_strings(fps, "+", 0, NULL);
  directory_get_from_all_authorities(DIR_PURPOSE_FETCH_STATUS_VOTE, 0,
                                     resource);
  tor_free(resource);
  SMARTLIST_FOREACH(fps, char *, cp, tor_free(cp));
  smartlist_free(fps);
}
