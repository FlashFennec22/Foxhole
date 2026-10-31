# Foxhole, a Rust-based System Level Adblocker

Foxhole is a simple set-and-forget ad blocker for Windows 11 which operates at the system level. There's nothing to configure - just install it and forget it's there.

## How does it work?

Foxhole checks your outgoing DNS requests against an always up-to-date blocklist. If the connection points at a known advertising domain, Foxhole simply refuses the connection so the ad doesn't load. DNS requests are routed to Cloudflare over HTTPS by default. If Cloudflare goes down, Foxhole temporarily falls back to Quad9. If HTTPS-Over-DNS fails, it falls back to basic UDP. Blocking is provided by the Hagezi Pro+ blocklist, which attempts to block known trackers and malware in addition to advertisements.

## Does it work on everything?

Only most things. Sites or apps which serve their own video ads (Such as Youtube, Twitch) still get through as there's not much that can be done about these at the DNS level. The vast majority of banner ads and trackers should be stopped, however.

## What should I be aware of?

Content blocking of any kind implies a risk of bumping into false positives. You might also find that sponsored links on some shopping sites are non-responsive, if they show at all. If you're encountering unexpected connection issues, try disabling protection via the tray icon. If ads aren't being blocked as expected, go to your browser's DNS settings and ensure that it's set to use system DNS.

## How do I install Foxhole?

Download the installer at the releases page: https://github.com/FlashFennec22/Foxhole/releases

It's brand new software, so smartscreen might complain. Feel free to create an issue if you encounter any other installation problems.

## How do I uninstall Foxhole?

Right click the windows icon on your taskbar, select Installed Apps, scroll to Foxhole DNS Ad Blocker, click the hamburger menu to the right and then Uninstall.

## Is there a way I can help support development?

Feel free to leave me a tip over on my Ko-Fi: https://ko-fi.com/flashfennec

## Thanks and considerations

Thanks to my longtime friend RocketKnight1 for his improvements upon my initial implementation and to the Hagezi team whose tireless work makes the internet a better place for all of us.
