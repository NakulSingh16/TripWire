// TripVuln SPA bundle (minified-style API layer)
const API = "/api/v3";
const api = { get: (u) => fetch(u, { headers: hdr() }).then(r => r.json()), post: (u, b) => fetch(u, { method: "POST", headers: hdr(), body: JSON.stringify(b) }).then(r => r.json()) };
function hdr() { return { "Content-Type": "application/json", Authorization: "Bearer " + localStorage.token }; }
export const login = (u, p) => api.post(API + "/auth/login", { username: u, password: p });
export const logout = () => api.post(API + "/auth/logout", {});
export const me = () => api.get(API + "/me");
export const updateMe = (b) => fetch(API + "/me", { method: "PATCH", headers: hdr(), body: JSON.stringify(b) });
export const search = (city, sort) => api.get(`${API}/hotels/search?city=${city}&sort=${sort}`);
export const hotel = (id) => api.get(API + "/hotels/" + id);
export const addTraveller = (t) => api.post(API + "/travellers", t);
export const traveller = (id) => api.get(API + "/travellers/" + id);
export const quote = (q) => api.post(API + "/quotes", q);
export const book = (b) => api.post(API + "/bookings", b);
export const bookings = () => api.get(API + "/bookings");
export const booking = (id) => api.get(`${API}/bookings/${id}`);
export const pay = (id, b) => api.post(`${API}/bookings/${id}/pay`, b);
export const confirm = (id, b) => api.post(`${API}/bookings/${id}/confirm`, b);
export const cancel = (id) => api.post(`${API}/bookings/${id}/cancel`, {});
export const refund = (id) => api.post(API + "/refunds", { booking_id: id });
export const wallet = () => api.get(API + "/wallet");
export const invoice = (id) => api.get(API + "/invoices/" + id);
export const voucher = (id, note) => api.get(`${API}/vouchers/${id}?note=${note}`);
export const agency = () => api.get(API + "/agency/profile");
export const users = () => api.get(API + "/agency/users");
export const addUser = (u) => api.post(API + "/agency/users", u);   // admin UI only
export const setBank = (b) => fetch(API + "/agency/bank-account", { method: "PUT", headers: hdr(), body: JSON.stringify(b) });
export const setEmail = (b) => fetch(API + "/agency/email", { method: "PUT", headers: hdr(), body: JSON.stringify(b) });
export const addWebhook = (u) => api.post(API + "/supplier/webhooks", { url: u });
export const sso = (n) => (location.href = API + "/auth/callback?next=" + encodeURIComponent(n));
