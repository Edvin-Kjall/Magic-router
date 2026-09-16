// Tracking-parameter stripping — distilled from the AdGuard URL Tracking
// filter (the generic $removeparam list) plus per-host rules for the sites
// people actually share. A blocklist, not an allowlist: anything not listed
// is kept, so stripping can never break a link — worst case a tracker
// survives. Global entries are safe on ANY site; per-host entries are only
// stripped on their hosts (e.g. `s` is a tracker on twitter/x but a real
// param elsewhere). Case-insensitive; `*` = prefix wildcard.
//
// Seal-time only: the stripped URL is what gets encrypted — nothing about
// stripping is recorded in the envelope.

const GLOBAL = new Set(`
a8 action_object_map action_ref_map action_type_map adc_publisher adc_token
adfrom adj_campaign adj_creative adj_label adj_t adjust_adgroup adjust_campaign
adjust_creative adjust_referrer adjust_tracker adjust_tracker_limit admitad_uid
adobe_mc_ref adobe_mc_sdid adsterra_clid adsterra_placement_id af_ad af_adset
af_click_lookback af_force_deeplink af_xp aiad_clid analytics_context
analytics_trace_id asgtbndr at_campaign at_campaign_type at_creation
at_emailtype at_link at_link_id at_link_origin at_link_type at_medium
at_ptr_name at_recipient_id at_recipient_list at_send_date awc bance_xuid
_bdadid bemobdata beyond_uzcvid beyond_uzmcvid _bhlid _branch_match_id
_branch_referrer bsft_aaid bsft_clkid bsft_eid bsft_ek bsft_mid bsft_uid btag
cjdata cjevent clckid _clde _cldee cm_cr cm_me cmpid cstrackid cuid cx_click
cx_recsOrder cx_recsWidget dclid dpg_campaign dpg_content dpg_medium dpg_source
ebisAdID ebisOther1 ebisOther2 ebisOther3 ebisOther4 ebisOther5 elq elqaid
elqak elqat elqCampaignId elqTrackId emcs_t eml-mediaplan eml-name
eml-publisher ems_dl erid eurl external_click_id famad_xuid fb_action_ids
fb_action_types fbadid fbclid fb_comment_id fb_ref fb_source ftag _ga
gad_campaignid gad_source gbraid gci gclid gclsrc _gl gps_adid guccounter
guce_referrer guce_referrer_sig hsa_acc hsa_ad hsa_cam hsa_grp hsa_kw hsa_la
hsa_mt hsa_net hsa_ol hsa_src hsa_tgt hsa_ver hsCtaTracking _hsenc __hsfp
_hsmi __hssc __hstc iclid int_campaign int_content int_medium int_source
int_term __io_lv _io_session_id ir_adid ir_campaignid irclickid irgwc
ir_partnerid is_retargeting itm_campaign itm_content itm_medium itm_source
itm_term janet jmtyClId ldtag_cl line_uid link_source loclid lt_r _ly_c _ly_r
maf mc_cid mc_eid mindbox-click-id mindbox-message-key mkt_tok ml_subscriber
ml_subscriber_hash msclkid mt_adset mt_campaign mt_click_id mt_creative
mt_link_id mtm_campaign mtm_cid mtm_content mt_medium mtm_group mtm_keyword
mtm_medium mtm_placement mtm_source mt_network mt_sub1 mt_sub2 mt_sub3 mt_sub4
mt_sub5 nb_expid_meta nb_placement nx_source oly_anon_id oly_enc_id _ope
_openstat oprtrack personaclick_input_query personaclick_search_query
pk_campaign pk_medium pk_source pk_vid ranEAID ranMID ranSiteID rb_clickid
recommended_by recommended_code rtkcid s_cid _sgm_action _sgm_campaign
_sgm_pinned _sgm_source _sgm_term sms_click sms_source sms_uph
spot_im_redirect_source srclt srsltid sscid taid Tcsack tduid tgclid ttclid
twclid tw_medium tw_profile_id tw_source unicorn_click_id user_email_address
usqp utm_ad utm_adgroup utm_adset utm_affiliate utm_brand utm_campaign
utm_campaignid utm_campaign_name utm_channel utm_cid utm_compaign utm_content
utm_creative utm_email utm_emailid utm_emcid utm_emmid utm_id utm_id_
utm_journey_id utm_keyword utm_lob utm_medium utm_name utm_newsletterid
utm_place utm_prid utm_product utm_pubreferrer utm_reader utm_referrer
utm_roistat utm_serial utm_servlet utm_session utm_siteid utm_social
utm_social-type utm_source utm_source_code utm_source_platform utm_supplier
utm_swu utm_tag utm_term utm_umguk utm_userid utm_viz_id utm_wave uzcid
vc_lpp vero_conv vero_id vs_campaign_id vsm_cid vsm_pid vsm_type wbraid
wickedid winflncrtag wt_mc x-a-medium x-clickref x-source xtor yclid yj_r
ymid ym_tracking_id ysclid _zucks_suid
`.trim().split(/\s+/));

// Prefix families — utm_* and mtm_* are tracker namespaces by design; any
// future variant is caught even if it isn't in the list above.
const GLOBAL_PREFIXES = ['utm_', 'mtm_', 'wt_', 'ga_', 'pk_'];

// Well-known per-host rules (AdGuard domain-scoped rules + famous ones it
// doesn't list). Values support a trailing * prefix wildcard.
const PER_HOST = {
  amazon: ['asc_*', 'crid', 'dib', 'dib_tag', 'linkCode', 'pd_rd_*', 'psc', 'qid', 'ref', 'ref_', 'refRID', 'smid', 'sprefix', 'sr', 'tag'],
  'amzn.to': ['asc_*', 'ref', 'ref_'],
  'youtube.com': ['si', 'feature', 'kw', 'embeds_*', 'source_ve_path', 'pp'],
  'youtu.be': ['si', 'feature'],
  youtubekids: ['embeds_*', 'source_ve_path'],
  'youtube-nocookie': ['embeds_*', 'source_ve_path'],
  twitter: ['s', 't', 'cxt', 'ref_src', 'refsrc', 'ref_url', 'vertical', 'related'],
  'x.com': ['s', 't', 'cxt', 'ref_src', 'refsrc', 'ref_url', 'vertical', 'related'],
  instagram: ['igshid', 'igsh', 'img_index', 'xmt'],
  threads: ['igshid', 'igsh', 'xmt'],
  tiktok: ['_d', '_t', 'checksum', 'sec_uid', 'u_code', 'preview_pb', 'share_*', 'is_from_webapp', 'sender_device', 'sender_web_id', 'web_id', 'region', 'mid', 'timestamp', 'user_id', 'copy_link'],
  linkedin: ['trk', 'trkInfo', 'trkCampaign', 'refId', 'trackingId', 'midSig', 'midToken', 'originalReferer', 'original_referer', 'originalSubdomain', 'veh', 'lipi', 'licu', 'upsellOrderOrigin'],
  reddit: ['ref', 'ref_source', 'rdt_cid', 'correlation_id'],
  spotify: ['si', 'context', 'nd', 'dlsi'],
  netflix: ['trackId', 'tctx', 'jbv'],
  ebay: ['_trkparms', '_trksid', 'mkevt', 'mkcid', 'mkrid', 'campid', 'toolid', 'customid', 'amdata', 'var', 'hash', 'g'],
  bing: ['cvid', 'nclid', 'epi', 'form', 'sk', 'sp', 'sc', 'qs', 'pq', 'ghsh', 'ghacc', 'ghpl'],
  microsoft: ['cvid', 'nclid', 'epi', 'ocid'],
  msn: ['cvid', 'ocid'],
  xbox: ['epi'],
  bbc: ['ns_campaign', 'ns_fee', 'ns_linkname', 'ns_mchannel', 'ns_source', 'ocid'],
  nytimes: ['smid', 'smtyp', 'spsp', 'smid2'],
  google: ['ved', 'ei', 'usg', 'sa', 'sqi', 'iflsig', 'ictx', 'sca_esv', 'source', 'biw', 'bih', 'dpr', 'psi', 'gs_lp', 'gs_l', 'sei', 'client', 'uact', 'oq', 'gs_lcp', 'sclient', 'gws_rd', 'pccc'],
  aliexpress: ['spm', 'scm', 'algo_pvid', 'algo_exp_id', 'aff_*', 'sk', 'ws_ab_test', 'btsid', 'ws_ab_test', 'pvid', 'tpp', 'pdp_npi', 'gps-id', 'gatewayAdapt', 'tt'],
  aliyun: ['spm'],
  sohu: ['spm'],
  lazada: ['spm', 'scm', 'acm', 'clickTrackInfo', 'laz_trackid', 'mkttid', 'trafficFrom', 'hybrid'],
  taobao: ['spm', 'scm', 'union_lens', 'abbucket', 'ali_*', 'app', 'bc_fl_src', 'ns', 'pvid', 'sku', 'utparam'],
  tmall: ['spm', 'scm', 'union_lens', 'abbucket', 'pvid', 'utparam', 'sku'],
  shein: ['from_country', 'ici', 'mallCode', 'phone_code', 'ref', 'src_module', 'src_tab_page_id', 'attr_ids', 'goods_attr', 'goods_sn', 'mall_goods_id'],
  'twitch.tv': ['tt_content', 'tt_medium'],
  walmart: ['athbdg', 'athena', 'adsRedirect', 'deferredStackForce'],
  nhk: ['cid'],
  nikkei: ['i_cid', 'n_cid', 'sub_rt'],
  note: ['sub_rt'],
  rakuten: ['l-id', 'scid', 's-id'],
  vk: ['recom', 'trackcode'],
  'vk.ru': ['recom', 'trackcode'],
  yandex: ['search_domain', 'search_source'],
  'ya.ru': ['search_domain', 'search_source'],
  otto: ['ActionID', 'AffiliateID', 'campid'],
  decathlon: ['cvrid', 'cvrpid', 'cvrsid', 'tag3', 'wgexpiry', 'wgu'],
  ibood: ['tag3', 'wgexpiry', 'wgu'],
  proton: ['phfp'],
  douban: ['dt_dapp'],
  '163.com': ['dt_dapp'],
  naver: ['frm', 'NaPm'],
  dmm: ['dmmref', 'i3_ord', 'i3_ref'],
  defenseone: ['oref'],
  govexec: ['oref'],
  nextgov: ['oref'],
  'route-fifty': ['oref'],
};

// hostname → matched key, e.g. 'www.amazon.co.uk' → 'amazon', 'm.x.com' → 'x.com'
function hostKey(host) {
  const h = host.toLowerCase().replace(/^www\./, '').replace(/^m\./, '');
  for (const k of Object.keys(PER_HOST)) {
    if (h === k || h.endsWith('.' + k) || h.startsWith(k + '.')) return k;
  }
  return null;
}

function matches(name, rule) {
  return rule.endsWith('*')
    ? name.startsWith(rule.slice(0, -1).toLowerCase())
    : name === rule.toLowerCase();
}

// stripTrackingParams(url) → { url, removed: [names…] }
// Surgical on the raw string — everything except removed params survives
// byte-for-byte (order, encoding, fragment, trailing-slash style). Never
// throws; anything it can't parse comes back unchanged.
export function stripTrackingParams(input) {
  const s = String(input);
  const removed = [];
  if (!/^https?:\/\//i.test(s)) return { url: s, removed };
  const hm = /^https?:\/\/([^/?#]+)/i.exec(s);
  const hostRules = hm ? PER_HOST[hostKey(hm[1].split(':')[0])] ?? [] : [];

  const hashIdx = s.indexOf('#');
  const head = hashIdx === -1 ? s : s.slice(0, hashIdx);
  const frag = hashIdx === -1 ? '' : s.slice(hashIdx);
  const qIdx = head.indexOf('?');
  if (qIdx === -1) return { url: s, removed };

  const kept = [];
  for (const part of head.slice(qIdx + 1).split('&')) {
    const eq = part.indexOf('=');
    const rawName = eq === -1 ? part : part.slice(0, eq);
    let n;
    try {
      n = decodeURIComponent(rawName.replace(/\+/g, ' ')).toLowerCase();
    } catch {
      n = rawName.toLowerCase();
    }
    if (
      GLOBAL.has(n) ||
      GLOBAL_PREFIXES.some((p) => n.startsWith(p)) ||
      hostRules.some((r) => matches(n, r))
    ) {
      removed.push(rawName);
    } else {
      kept.push(part);
    }
  }
  if (!removed.length) return { url: s, removed };
  const out = kept.length
    ? head.slice(0, qIdx) + '?' + kept.join('&') + frag
    : head.slice(0, qIdx) + frag;
  return { url: out, removed };
}
