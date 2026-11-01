# Android Boot Log Analyzer

A dependency-free Python command-line tool that scans Android `dmesg` and `logcat` text logs, flags common boot problems, estimates the elapsed time represented by the log, finds slow initialization actions, and writes a JSON or HTML report.

> This is a learning project that uses simple text rules. It is not an Android platform diagnostic and cannot prove that a flagged line caused a slow or failed boot. Review surrounding lines and confirm findings on the target device.

## Requirements

- Python 3.9 or newer
- Optional: Android Platform Tools (`adb`) to collect a log from an emulator or device

There are no third-party Python dependencies.

## Quick start

From this folder, run:

```sh
python boot_analyzer.py sample-logs/sample-boot.log --format json --output reports/sample-report.json
```

Create an HTML report:

```sh
python boot_analyzer.py sample-logs/sample-boot.log --format html --output reports/sample-report.html
```

Or print a JSON report directly in the terminal:

```sh
python boot_analyzer.py sample-logs/sample-boot.log
```

Use `--slow-ms 500` to lower the default slow-stage threshold of 1000 ms. Run `python boot_analyzer.py --help` for all options.

## Project website

The project website source is in `docs/`. After enabling GitHub Pages, it will be available at:

<https://khandelwalbhavya853-coder.github.io/android-boot-log-analyzer/>

To publish it, open the repository's **Settings → Pages**, choose **Deploy from a branch**, select branch `main` and folder `/docs`, then click **Save**. GitHub Pages may take a few minutes to publish the first build.

## Collecting logs with ADB

Enable USB debugging (or start an emulator), connect the device, and check that ADB can see it:

```sh
adb devices
```

Capture the current kernel ring buffer:

```sh
adb shell dmesg > boot-dmesg.log
```

Capture Android system and framework logs:

```sh
adb logcat -b all -d -v threadtime > boot-logcat.log
```

Then analyze either file:

```sh
python boot_analyzer.py boot-dmesg.log --format html --output boot-report.html
python boot_analyzer.py boot-logcat.log --format json --output boot-report.json
```

For a clean boot capture, clear logcat, reboot the device, wait for startup, then dump logcat:

```sh
adb logcat -b all -c
adb reboot
# Wait for the device to finish booting, then:
adb logcat -b all -d -v threadtime > boot-logcat.log
```

Some production builds restrict access to `dmesg`; use an emulator or a permitted development build. Avoid sharing logs without checking them for serial numbers, account data, paths, or other private information.

## What the analyzer reports

- **Severity:** critical, error, or warning, inferred from log level and common wording.
- **Category:** kernel, driver, firmware, SELinux, init, framework, or general.
- **Boot time:** the span between recognized timestamps. This is the time covered by the log, not necessarily the device's exact power-on-to-home-screen time.
- **Slow stages:** init/service lines that include a duration at or above the chosen threshold.
- **Recommendations:** general next steps based on detected categories.

The rule signatures live in `boot_analyzer.py` and can be extended for device- or vendor-specific messages. Duplicate identical findings are collapsed; the first matching line is retained.

## Repository layout

```text
boot_analyzer.py          Analyzer and command-line interface
sample-logs/              Synthetic log for a device-independent demo
reports/                  Example JSON and HTML outputs
tests/                    unittest test cases
```

The sample log is synthetic and does not contain measurements from a real device.

## Tests

Test cases use Python's built-in `unittest` framework:

```sh
python -m unittest discover -s tests -v
```

## Suggested extensions

- Add known-good and known-bad real-device fixtures with sensitive data removed.
- Parse additional timestamp formats and correlate multiple log buffers.
- Compare log events with Android's `sys.boot_completed` property.
- Add configurable vendor rules and severity overrides.
- Add a baseline comparison to highlight regressions between builds.

## License

MIT. See [LICENSE](LICENSE).
