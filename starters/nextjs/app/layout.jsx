import "./style.css";

export const metadata = {
  title: "ĀML Interface Firewall | Next.js example",
  description: "A verifiable server-side interface governance example"
};

export default function RootLayout({ children }) {
  return <html lang="en"><body>{children}</body></html>;
}
