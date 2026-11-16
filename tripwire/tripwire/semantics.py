"""Parameter semantic tagging. The planner keys attack rules on these classes.
`compare()` benchmarks rules vs TF-IDF+LR vs MiniLM kNN/LR vs hybrid (see eval/semantics_results.json)."""
import re, json

CLASSES = ["ref_id", "tenant_id", "privilege", "money", "quantity", "coupon", "url", "redirect", "search", "sort",
           "credential", "pii", "other"]

# Seed set: (name, endpoint context, label, family). Families = naming conventions of different public API styles,
# used for GROUPED cross-validation so test names never come from the same convention as training names.
SEED = """
stripe|/v1/charges|amount|money;currency|/v1/charges|currency|other;customer|/v1/charges|customer|ref_id;source|/v1/charges|source|ref_id
stripe|/v1/refunds|charge|ref_id;payment_intent|/v1/refunds|payment_intent|ref_id;reason|/v1/refunds|reason|other;amount_off|/v1/coupons|amount_off|money
stripe|/v1/coupons|percent_off|money;promotion_code|/v1/checkout|promotion_code|coupon;success_url|/v1/checkout|success_url|redirect;cancel_url|/v1/checkout|cancel_url|redirect
stripe|/v1/webhook_endpoints|url|url;quantity|/v1/subscription_items|quantity|quantity;unit_amount|/v1/prices|unit_amount|money;limit|/v1/charges|limit|sort
stripe|/v1/customers/search|query|search;starting_after|/v1/charges|starting_after|sort;account|/v1/transfers|account|tenant_id;destination|/v1/transfers|destination|tenant_id
stripe|/v1/customers|email|pii;phone|/v1/customers|phone|pii;name|/v1/customers|name|pii;application_fee_amount|/v1/charges|application_fee_amount|money
stripe|/v1/invoices|invoice|ref_id;discounts|/v1/invoices|discounts|coupon;tax_rates|/v1/invoices|tax_rates|money;metadata|/v1/charges|metadata|other
shopify|/admin/orders.json|order_id|ref_id;line_items|/admin/orders.json|line_items|other;total_price|/admin/orders.json|total_price|money;discount_codes|/admin/orders.json|discount_codes|coupon
shopify|/admin/orders.json|financial_status|other;shop_id|/admin/shop.json|shop_id|tenant_id;customer_id|/admin/customers|customer_id|ref_id;variant_id|/admin/products|variant_id|ref_id
shopify|/admin/products.json|title|search;sort_order|/admin/products.json|sort_order|sort;page_info|/admin/products.json|page_info|sort;inventory_quantity|/admin/variants|inventory_quantity|quantity
shopify|/admin/webhooks.json|address|url;callback_url|/admin/carrier_services|callback_url|url;return_to|/account/login|return_to|redirect;password|/account/login|password|credential
shopify|/admin/staff|permissions|privilege;account_owner|/admin/staff|account_owner|privilege;compare_at_price|/admin/variants|compare_at_price|money;phone|/admin/customers|phone|pii
amadeus|/v2/shopping/flight-offers|originLocationCode|search;destinationLocationCode|/v2/shopping/flight-offers|destinationLocationCode|search;adults|/v2/shopping/flight-offers|adults|quantity
amadeus|/v2/shopping/flight-offers|children|quantity;infants|/v2/shopping/flight-offers|infants|quantity;maxPrice|/v2/shopping/flight-offers|maxPrice|money;currencyCode|/v2/shopping/flight-offers|currencyCode|other
amadeus|/v1/booking/flight-orders|flightOrderId|ref_id;travelerId|/v1/booking/flight-orders|travelerId|ref_id;documentNumber|/v1/booking/flight-orders|documentNumber|pii;dateOfBirth|/v1/booking/flight-orders|dateOfBirth|pii
amadeus|/v1/booking/hotel-bookings|offerId|ref_id;roomQuantity|/v3/shopping/hotel-offers|roomQuantity|quantity;checkInDate|/v3/shopping/hotel-offers|checkInDate|other;hotelIds|/v3/shopping/hotel-offers|hotelIds|ref_id
amadeus|/v1/security/oauth2/token|client_secret|credential;grant_type|/v1/security/oauth2/token|grant_type|other;cardNumber|/v1/booking/hotel-bookings|cardNumber|pii;vendorCode|/v1/booking/hotel-bookings|vendorCode|other
amadeus|/v1/reference-data/locations|keyword|search;subType|/v1/reference-data/locations|subType|sort;page[limit]|/v1/reference-data/locations|page[limit]|sort;nonStop|/v2/shopping/flight-offers|nonStop|other
github|/repos/{owner}/{repo}/issues|state|other;labels|/repos/{owner}/{repo}/issues|labels|other;sort|/repos/{owner}/{repo}/issues|sort|sort;direction|/repos/{owner}/{repo}/issues|direction|sort
github|/search/code|q|search;per_page|/search/code|per_page|sort;org|/orgs/{org}/members|org|tenant_id;role|/orgs/{org}/memberships|role|privilege
github|/repos/{owner}/{repo}/hooks|config.url|url;permission|/repos/{owner}/{repo}/collaborators|permission|privilege;site_admin|/users|site_admin|privilege;issue_number|/repos/{owner}/{repo}/issues|issue_number|ref_id
github|/user|email|pii;otp|/session|otp|credential;redirect_uri|/login/oauth/authorize|redirect_uri|redirect;access_token|/login/oauth/access_token|access_token|credential
travel|/api/bookings|bookingRef|ref_id;pnr|/api/bookings|pnr|ref_id;agencyId|/api/bookings|agencyId|tenant_id;subAgentId|/api/agents|subAgentId|tenant_id
travel|/api/bookings|fare|money;markup|/api/bookings|markup|money;netFare|/api/bookings|netFare|money;baseFare|/api/bookings|baseFare|money
travel|/api/bookings|paxCount|quantity;noOfNights|/api/hotel/book|noOfNights|quantity;rooms|/api/hotel/book|rooms|quantity;promoCode|/api/bookings|promoCode|coupon
travel|/api/hotel/search|cityCode|search;hotelName|/api/hotel/search|hotelName|search;sortBy|/api/hotel/search|sortBy|sort;orderBy|/api/hotel/search|orderBy|sort
travel|/api/payments|paymentId|ref_id;holdId|/api/hold|holdId|ref_id;quoteId|/api/quote|quoteId|ref_id;voucherNo|/api/voucher|voucherNo|ref_id
travel|/api/agents|isAdmin|privilege;userRole|/api/agents|userRole|privilege;creditLimit|/api/agents|creditLimit|privilege;canIssueTicket|/api/agents|canIssueTicket|privilege
travel|/api/supplier|callbackUrl|url;webhookUrl|/api/supplier|webhookUrl|url;returnUrl|/api/payments|returnUrl|redirect;next|/auth/sso|next|redirect
travel|/api/passengers|passportNo|pii;nationality|/api/passengers|nationality|other;mobile|/api/passengers|mobile|pii;paxName|/api/passengers|paxName|pii
travel|/api/auth|resetToken|credential;newPassword|/api/auth|newPassword|credential;refreshToken|/api/auth|refreshToken|credential;userId|/api/users|userId|tenant_id
travel|/api/refund|refundAmount|money;cancellationCharge|/api/refund|cancellationCharge|money;walletBalance|/api/wallet|walletBalance|money;topupAmount|/api/wallet|topupAmount|money
travel|/api/coupon|couponCode|coupon;voucherCode|/api/redeem|voucherCode|coupon;discountPct|/api/coupon|discountPct|money;qty|/api/addons|qty|quantity
crm|/rest/contacts|contact_id|ref_id;owner_id|/rest/contacts|owner_id|tenant_id;tenant|/rest/contacts|tenant|tenant_id;org_id|/rest/orgs|org_id|tenant_id
crm|/rest/contacts|first_name|pii;last_name|/rest/contacts|last_name|pii;ssn|/rest/contacts|ssn|pii;birthdate|/rest/contacts|birthdate|pii
crm|/rest/contacts|filter|sort;fields|/rest/contacts|fields|sort;offset|/rest/contacts|offset|sort;search_term|/rest/contacts|search_term|search
crm|/rest/users|is_superuser|privilege;group_ids|/rest/users|group_ids|privilege;scopes|/rest/apikeys|scopes|privilege;api_key|/rest/apikeys|api_key|credential
crm|/rest/import|file_url|url;image_url|/rest/users|avatar_url|url;redirect|/rest/logout|redirect|redirect;continue|/rest/login|continue|redirect
crm|/rest/deals|deal_value|money;price_per_unit|/rest/deals|price_per_unit|money;units|/rest/deals|units|quantity;seats|/rest/billing|seats|quantity
crm|/rest/notes|body|other;subject|/rest/notes|subject|other;description|/rest/tasks|description|other;status|/rest/tasks|status|other
"""

def load_seed():
    rows = []
    for line in SEED.strip().splitlines():
        fam, rest = line.split("|", 1)
        for item in rest.split(";"):
            ctx, name, label = item.split("|")[-3:]
            rows.append({"name": name, "ctx": ctx, "label": label, "family": fam})
    return rows

# --------------------------------------------------------------- rules (value heuristics + name patterns)
RULES = [
    ("credential", r"pass(word|wd|code)?$|password|pwd|secret|otp|token|api.?key|pin(code)?$"),
    ("redirect", r"^(next|redirect|return(_?to|_?url)?|continue|success.?url|cancel.?url|redirect.?uri|goto|dest)$"),
    ("url", r"url|uri|webhook|callback|endpoint|address$"),
    ("coupon", r"coupon|promo|discount.?code|voucher.?code|redeem"),
    ("privilege", r"role|admin|perm|privilege|scope|superuser|group|credit.?limit|can[A-Z_]|is_?staff|owner$"),
    ("tenant_id", r"(agency|tenant|org|shop|account|company|sub.?agent|user)(_?id)?$|^org$|^tenant$"),
    ("money", r"price|amount|fare|total|markup|fee|cost|charge|balance|discount|tax|percent|value$"),
    ("quantity", r"qty|quantity|count|nights|rooms|pax|adults|children|infants|seats|units"),
    ("pii", r"passport|email|phone|mobile|dob|birth|ssn|card|name$|document.?number|address"),
    ("sort", r"sort|order|direction|limit|offset|page|per.?page|fields|filter|starting|after|before"),
    ("search", r"^q$|query|search|keyword|term|city|location|title|hotel.?name"),
    ("ref_id", r"(_|[a-z])(id|ids|ref|no|number)$|^id$|pnr|invoice|order|charge|source|customer"),
]
_rx = [(c, re.compile(p, re.I)) for c, p in RULES]

def rule_label(name, value=None):
    if isinstance(value, str):
        if re.match(r"^https?://", value): return "url", 1.0
        digits = re.sub(r"\D", "", value)
        if 13 <= len(digits) <= 19 and _luhn(digits): return "pii", 1.0
    leaf = name.split(".")[-1].split("[")[0].replace("-", "_")
    for c, rx in _rx:
        if rx.search(leaf):
            return c, 0.9
    return "other", 0.3

def _luhn(d):
    s = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch) * (2 if i % 2 else 1); s += n - 9 if n > 9 else n
    return s % 10 == 0

def _split(name):
    return re.sub(r"([a-z])([A-Z])", r"\1 \2", name).replace("_", " ").replace(".", " ").replace("-", " ").lower()

def text(r):
    return f"{_split(r['name'])} | {r['ctx']}"

# --------------------------------------------------------------- models
class Tagger:
    """Chosen model is set by compare() results; default = what won (see eval/semantics_results.json)."""
    def __init__(self, kind="hybrid_tfidf"):
        self.kind = kind; self.model = None
    def fit(self, rows):
        from sklearn.pipeline import make_pipeline
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        if self.kind in ("tfidf", "hybrid_tfidf"):
            self.model = make_pipeline(TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True),
                                       LogisticRegression(max_iter=3000, C=10, class_weight="balanced"))
            self.model.fit([text(r) for r in rows], [r["label"] for r in rows])
        elif self.kind.startswith("emb"):
            from sklearn.neighbors import KNeighborsClassifier
            X = _embed([text(r) for r in rows]); y = [r["label"] for r in rows]
            self.model = (KNeighborsClassifier(5, weights="distance", metric="cosine") if self.kind == "emb_knn"
                          else LogisticRegression(max_iter=3000, C=10, class_weight="balanced")).fit(X, y)
        return self
    def predict(self, rows):
        out = []
        if self.kind == "rules":
            return [rule_label(r["name"], r.get("value"))[0] for r in rows]
        X = [text(r) for r in rows]
        if self.kind.startswith("emb"):
            X = _embed(X)
        proba = self.model.predict_proba(X); cls = self.model.classes_
        for r, p in zip(rows, proba):
            ml, conf = cls[p.argmax()], p.max()
            if self.kind.startswith("hybrid"):
                rl, rc = rule_label(r["name"], r.get("value"))
                out.append(rl if (rc >= 1.0 or (rl != "other" and conf < 0.5)) else ml)
            else:
                out.append(ml)
        return out

_EMB = None
def _embed(texts):
    global _EMB
    if _EMB is None:
        from sentence_transformers import SentenceTransformer
        _EMB = SentenceTransformer("all-MiniLM-L6-v2")
    return _EMB.encode(texts, normalize_embeddings=True, show_progress_bar=False)

def compare(external=None, out="eval/semantics_results.json"):
    """Leave-one-family-out CV on the seed set + held-out external set (target params labelled by hand)."""
    import time
    from sklearn.metrics import f1_score, accuracy_score
    rows = load_seed(); fams = sorted({r["family"] for r in rows})
    kinds = ["rules", "tfidf", "hybrid_tfidf", "emb_knn", "emb_lr"]
    res = {}
    for k in kinds:
        t0 = time.time(); ys, ps = [], []
        for f in fams:
            tr = [r for r in rows if r["family"] != f]; te = [r for r in rows if r["family"] == f]
            m = Tagger(k).fit(tr) if k != "rules" else Tagger(k)
            ps += m.predict(te); ys += [r["label"] for r in te]
        ext = {}
        if external:
            m = Tagger(k).fit(rows) if k != "rules" else Tagger(k)
            pe = m.predict(external); ye = [r["label"] for r in external]
            ext = {"ext_acc": round(accuracy_score(ye, pe), 3), "ext_macro_f1": round(f1_score(ye, pe, average="macro", zero_division=0), 3),
                   "ext_errors": [(r["name"], y, p) for r, y, p in zip(external, ye, pe) if y != p]}
        res[k] = {"lofo_acc": round(accuracy_score(ys, ps), 3), "lofo_macro_f1": round(f1_score(ys, ps, average="macro", zero_division=0), 3),
                  "seconds": round(time.time() - t0, 1), **ext}
    json.dump(res, open(out, "w"), indent=1)
    return res
