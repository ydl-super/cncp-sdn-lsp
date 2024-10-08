
# Copyright (c) 2021 PANTHEON.tech.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

include_directories(${CMAKE_SOURCE_DIR})
message(STATUS "VPP_WORKSPACE: ${VPP_WORKSPACE}")
include_directories(${VPP_WORKSPACE}/src/)

# for generated API headers:
include_directories(${CMAKE_BINARY_DIR})

add_vpp_plugin(abx
  SOURCES
  node.c
  abx.c
  abx_api.c
  abx_policy.c
  abx_if_attach.c

  MULTIARCH_SOURCES
  node.c

  API_FILES
  abx.api

  INSTALL_HEADERS
  abx_all_api_h.h
  abx_msg_enum.h

  COMPONENT vpp-plugin-abx
)
