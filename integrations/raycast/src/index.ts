import { Clipboard, getSelectedText, open } from "@raycast/api";

// Your Magic Router deployment origin (or a self-hosted instance).
const HOST = "https://YOUR-HOST";

type Args = { arguments: { url?: string } };

export default async function seal(args: Args) {
  let url = args.arguments.url?.trim();
  if (!url) {
    try {
      url = await getSelectedText();
    } catch {
      // nothing selected
    }
  }
  if (!url) url = await Clipboard.readText();
  url = url || "";
  const target = /^https?:\/\//i.test(url) ? url : "https://" + url;
  await open(`${HOST}/?url=${encodeURIComponent(target)}`);
}
