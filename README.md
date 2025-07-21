# TotallyNotSpyware v2 Redesigned
<img src="https://github.com/forcequitOS/tns-v2-newUI/blob/main/showcase.png?raw=true" width="35%">

## This is an (unofficial) complete redesign of TNS v2 for iOS 12.
**You can try it now at https://tns12.forcequit.cc!**

This modification most importantly adds support for **adding the page to your Home Screen as a web clip**, with an icon and even **offline support**!

This is an unofficial modification, so, do be careful, but I can say pretty confidently that this doesn't install malware or anything, and you can independently verify the source if you so desire.

## Troubleshooting / Info

**"A problem repeatedly occurred..."** - If you're in Safari and this message appears while you're trying to rejailbreak, reload the page. If you've added the page to your Home Screen, and solely wish to jailbreak from there, reboot your device. 

**Device reboots after "Jailbreaking..." for a few seconds** - Leave your device powered on and unlocked for 30-60 seconds before retrying again, it'll work eventually.

**Background gradient animates** - The re-jailbreak is not going to work. A likely cause can be that you're already jailbroken. Reload the page / reboot your device and try again.

**Device doesn't reflect updates to site** - I probably didn't update the AppCache manifest. Go to Settings > Safari > Clear History and Website Data and it'll get new data from the server.

## Full list of changes:

- Offline support, as long as you add it to Home Screen and run it once, you should be fine.
- Beloved fancy background gradient
- Credits as a collapsible list
- Graying out the rejailbreak button for unsupported devices (I just check user agents)
- No more found JOP chain alert (Worse for debugging I assume, but better to just rejailbreak your device.)
- (Obviously) Can add to Home Screen, and run full screen, not in Safari, with an app icon and a name. Revolutionary.
- Looks pretty now. Uses system font, etc. etc.
- Actual title and favicon, alongside some Open Graph metadata

## But as always, there is one more thing.

If someone can figure out how I could stop the page from scrolling and bouncing around all over the place, I'd be eternally grateful. But if not I don't really care either. Other than that, I think this is largely "pretty great", not much more to improve.

<sub>I've probably used the actual absolute messiest CSS I've ever written in my life to make this, oh well.</sub>
