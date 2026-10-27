import { createRoot } from "react-dom/client"

import UserPage from "./UserPage.tsx"
import "./index.css"

createRoot(document.getElementById("user-root")!).render(<UserPage />)
