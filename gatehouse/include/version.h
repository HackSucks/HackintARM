// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors

/*
 * gatehouse/include/version.h - Gatehouse's build-number versioning.
 *
 * Gatehouse is versioned by build number, not semver: six digits, two each
 * for the day, month and year of the build, optionally suffixed with "a"
 * (alpha), "b" (beta) or nothing (release).  The date half is taken from
 * __DATE__ at compile time, so a build is stamped automatically; only the
 * stage is set by hand, here.
 *
 * Examples: 181026a = 18 Oct 2026, alpha; 020327 = 2 Mar 2027, release.
 */
#ifndef GATEHOUSE_VERSION_H
#define GATEHOUSE_VERSION_H

/* "", "a" (alpha) or "b" (beta).  Empty means a release build. */
#define GH_VERSION_STAGE "a"

#define GH_STR_(x) #x
#define GH_STR(x)  GH_STR_(x)

#if defined(__clang__)
#define GH_COMPILER "clang " GH_STR(__clang_major__) "." \
    GH_STR(__clang_minor__) "." GH_STR(__clang_patchlevel__)
#elif defined(__GNUC__)
#define GH_COMPILER "gcc " GH_STR(__GNUC__) "." GH_STR(__GNUC_MINOR__) "." \
    GH_STR(__GNUC_PATCHLEVEL__)
#else
#define GH_COMPILER "unknown"
#endif

#define GH_BUILD_DATE __DATE__
#define GH_BUILD_TIME __TIME__

/*
 * Format this build's number into buf, which must hold at least 8 bytes
 * ("181026a" + NUL).  Returns buf so it can be dropped straight into a puts.
 */
const char *gh_version_string(char *buf);

#endif /* GATEHOUSE_VERSION_H */
