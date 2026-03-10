# Catenar Playground

Next.js 14 demo site for the Catenar Proof-of-Task verification system.

## Setup

1. Install dependencies:

   ```bash
   npm install
   ```

2. Create `.env.local` (or copy from `.env.local.example`):

   ```
   VERIFIER_API_URL=http://127.0.0.1:3000
   JWT_SECRET=your-secret-key
   ```

3. Start the Rust verifier backend (from repo root):

   ```bash
   cd verifier && cargo run
   ```

4. Start the Next.js dev server:

   ```bash
   npm run dev
   ```

   The Playground runs at [http://localhost:3001](http://localhost:3001). The verifier runs on port 3000.

## Flow

1. **Landing** → Sign in (any username/password for demo).
2. **Policy Builder** → Set `max_spend` and `restricted_endpoints`, register to get a policy commitment.
3. **Verification Playground** → Paste the policy commitment, build a trace, submit for verification. View PoT receipt or violation.
4. **SDK Sandbox** → Copy Python/cURL snippets with your policy commitment.
