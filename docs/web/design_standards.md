# Catenar Web Design & Robustness Standards

## 1. Visual Identity & UI/UX
- **Theme**: Strictly use a "Developer-Centric" Dark Mode.
- **Components**: Use **Shadcn/UI** for all interactive elements (buttons, inputs, cards).
- **Typography**: Use Sans-serif for prose and Monospace (e.g., JetBrains Mono) for all API data, hashes, and code snippets.
- **Responsiveness**: Implement Mobile-First design using Tailwind CSS breakpoints.

## 2. Robust Frontend Architecture
- **Framework**: Next.js 14+ (App Router).
- **State Management**: 
  - Use **TanStack Query (React Query)** for all server-state (fetching proofs, registering policies).
  - Use **Zustand** for lightweight client-state (e.g., UI toggles).
- **Form Handling**: Use **React Hook Form** integrated with **Zod** for client-side validation that matches the Rust backend schemas.
- **Loading States**: Implement Skeleton loaders for "In-Progress" cryptographic verifications to minimize perceived latency.

## 3. Data Synchronization
- **Polling/Sockets**: Since proof generation in Rust is near-instant, use TanStack Query's `refetchInterval` or WebSockets to show "Live" trace results as they arrive.
- **Error Boundaries**: Implement React Error Boundaries to catch and display API failures without crashing the entire Playground.
