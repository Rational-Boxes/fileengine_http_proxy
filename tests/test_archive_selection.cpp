// Copyright (C) 2026 James Hickman
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// archive_selection.h — the uid list behind "Download as ZIP" for selected items.
#include <gtest/gtest.h>

#include "archive_selection.h"

using namespace httpbridge::archive;

namespace {
const std::string A = "11111111-2222-3333-4444-555555555555";
const std::string B = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const char* kJson = "application/json";
const char* kForm = "application/x-www-form-urlencoded";
}  // namespace

TEST(ArchiveSelection, AnEmptyBodyMeansTheWholeFolder) {
    std::set<std::string> s; std::string err;
    EXPECT_EQ(parseSelection(kJson, "", s, err), SelectionParse::None);
    EXPECT_EQ(parseSelection("", "", s, err), SelectionParse::None);
    EXPECT_EQ(parseSelection(kJson, "{}", s, err), SelectionParse::None);
    EXPECT_EQ(parseSelection(kForm, "ticket=abc", s, err), SelectionParse::None);
}

TEST(ArchiveSelection, JsonArray) {
    std::set<std::string> s; std::string err;
    ASSERT_EQ(parseSelection(kJson, "{\"uids\":[\"" + A + "\",\"" + B + "\",\"" + A + "\"]}", s, err),
              SelectionParse::Ok) << err;
    EXPECT_EQ(s, (std::set<std::string>{A, B}));   // de-duplicated
}

TEST(ArchiveSelection, FormCommaListAndRepeatedFields) {
    std::set<std::string> s; std::string err;
    // The SPA's shape: the ticket rides along in the same body or the URL.
    ASSERT_EQ(parseSelection(std::string(kForm) + "; charset=UTF-8",
                             "ticket=x.y.z&uids=" + A + "%2C" + B, s, err), SelectionParse::Ok) << err;
    EXPECT_EQ(s, (std::set<std::string>{A, B}));
    ASSERT_EQ(parseSelection(kForm, "uids=" + A + "&uids=" + B + ",", s, err), SelectionParse::Ok) << err;
    EXPECT_EQ(s.size(), 2u);
}

TEST(ArchiveSelection, RefusesWhatIsNotAUidList) {
    std::set<std::string> s; std::string err;
    EXPECT_EQ(parseSelection(kJson, "{\"uids\":[]}", s, err), SelectionParse::Invalid);
    EXPECT_EQ(parseSelection(kJson, "{\"uids\":\"" + A + "\"}", s, err), SelectionParse::Invalid);
    EXPECT_EQ(parseSelection(kJson, "{\"uids\":[1,2]}", s, err), SelectionParse::Invalid);
    EXPECT_EQ(parseSelection(kJson, "not json", s, err), SelectionParse::Invalid);
    EXPECT_EQ(parseSelection(kForm, "uids=", s, err), SelectionParse::Invalid);
    EXPECT_EQ(parseSelection(kForm, "uids=../../etc", s, err), SelectionParse::Invalid);
    EXPECT_EQ(parseSelection(kForm, "uids=" + A + "%0Ainjected", s, err), SelectionParse::Invalid);
    EXPECT_EQ(parseSelection("text/plain", "uids=" + A, s, err), SelectionParse::Invalid);
}

TEST(ArchiveSelection, IsBounded) {
    std::set<std::string> s; std::string err;
    std::string body = "uids=";
    for (size_t i = 0; i <= kMaxSelection; ++i) {
        char buf[40];
        std::snprintf(buf, sizeof buf, "%08zx-0000-0000-0000-000000000000,", i);
        body += buf;
    }
    EXPECT_EQ(parseSelection(kForm, body, s, err), SelectionParse::Invalid);
    EXPECT_NE(err.find("more than"), std::string::npos) << err;
    EXPECT_EQ(parseSelection(kForm, std::string(kMaxSelectionBody + 1, 'a'), s, err), SelectionParse::Invalid);
}
