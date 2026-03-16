# unsubmy.email Roadmap

Current Stack: **FastAPI (Async)** | **PostgreSQL** | **Redis** | **Celery** | **Vanilla JS/Jinja2**

This roadmap tracks the evolution of unsubmy.email from its current robust backend state to a premium, modern SaaS product.

---

## ✅ Completed Foundations
- [x] **FastAPI Migration**: Fully async backend with dependency injection.
- [x] **Infrastructure**: Dockerized environment with PostgreSQL and Redis.
- [x] **Background Tasks**: Celery worker implementation for non-blocking email scanning.
- [x] **Real-time UX**: SSE (Server-Sent Events) for live scan progress.
- [x] **Database Architecture**: Relationship-based schema for Users, Accounts, and Links.

---

## 🚀 Phase 1: Security Hardening & Logic Refinement (High Priority)
*Focus: Protecting user data and fixing suboptimal legacy logic.*

- [ ] **1.1: Credential Encryption (Low-Hanging Fruit)**
    - Encrypt `LinkedAccount.credentials` at rest using `cryptography` (AES-256).
    - Implement a rotating `ENCRYPTION_KEY` via environment variables.
- [ ] **1.2: Truly Async Email Client**
    - The current `email_client.py` uses synchronous `imaplib`.
    - **Optimization**: Shift to an async library or optimize thread-pooling in Celery to prevent worker starvation during high-volume scans.
- [ ] **1.3: Robust Token Management**
    - Implement automatic OAuth2 token refreshing (Gmail/Google) to prevent "Connection Expired" errors.
- [ ] **1.4: API Validation (Pydantic)**
    - Fully utilize Pydantic models for all incoming request payloads to ensure type safety.

---

## 🎨 Phase 2: Frontend Modernization (The React Shift)
*Focus: Replacing brittle Vanilla JS/Jinja2 with a modern, maintainable Component Architecture.*

- [ ] **2.1: Vite + React + Tailwind Setup**
    - Initialize a modern frontend build system.
    - Establish a Design System (Colors, Typography, Glassmorphism components).
- [ ] **2.2: State Management (Zustand/React Query)**
    - Replace globally-scoped JS arrays with a reliable state management layer.
    - Use React Query for account/link synchronization and automatic caching.
- [ ] **2.3: Dashboard Componentization**
    - Break down the current single-template dashboard into reusable components: `AccountSidebar`, `ScanWidget`, `LinkList`, `FilterTabs`.
- [ ] **2.4: Unified UI/UX Polish**
    - Consistent Dark Mode support.
    - Framer Motion for micro-animations (scanners, link deletions).
    - Responsive mobile-first design.

---

## 🧠 Phase 3: Intelligence & Efficiency
*Focus: Automating the unsubscribe process and improving discovery.*

- [ ] **3.1: "One-Click" List-Unsubscribe Support**
    - Detect `List-Unsubscribe` headers (HTTP/Mailto).
    - Implement "unsub on behalf" logic directly from the dashboard.
- [ ] **3.2: AI-Powered Sender Categorization**
    - Use basic LLM or heuristic analysis to group senders (e.g., "Marketing", "Newsletters", "Spam").
- [ ] **3.3: Global Sender Reputation**
    - Track senders that ignore unsubscribe requests and alert other users.
- [ ] **3.4: Browser Extension**
    - A companion extension to "unsub on fly" while reading emails in Gmail/Outlook browser tabs.

---

## 🛠 Low-Hanging Fruits (Next Steps)
1. **Button UX Fix**: Ensure Dashboard buttons dynamically reflect states (e.g., "Add Account" if none exists).
2. **Scan Logic Fix**: Don't allow scans on invalid/missing credentials.
3. **Delete Logic**: Implement bulk deletion of selected senders.