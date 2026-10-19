import { normalizeEmail } from "./src/auth/users.ts";

const raw = "Daaeasdf@GmAiL.  com    "
const email = normalizeEmail(raw)
console.log(email);
