import { addMessages, init, locale } from "svelte-i18n";
import en from "./locales/en.json";
import fa from "./locales/fa.json";

addMessages("en", en);
addMessages("fa", fa);

const SAVED = "sni-spoofing.locale";
const initial =
  (typeof localStorage !== "undefined" && localStorage.getItem(SAVED)) || "en";

init({
  fallbackLocale: "en",
  initialLocale: initial,
});

// locale.subscribe fires synchronously with the current value on registration,
// so this single subscription handles both the initial DOM setup and every
// subsequent change — no separate eager applyDirection call needed.
locale.subscribe((value) => {
  if (!value) return;
  if (typeof localStorage !== "undefined") {
    localStorage.setItem(SAVED, value);
  }
  applyDirection(value);
});

function applyDirection(loc: string) {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  const isRTL = loc.startsWith("fa") || loc.startsWith("ar") || loc.startsWith("he");
  root.setAttribute("dir", isRTL ? "rtl" : "ltr");
  root.setAttribute("lang", loc);
}
