# Copyright (c) 2018 Cisco and/or its affiliates.
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


# Copyright (c) 2022 flexiWAN Ltd.
# This file is part of the FWAPP plugin.
# The FWAPP plugin is fork of the FDIO VPP ABF plugin.
# It enhances ABF with functionality required for Flexiwan Multi-Link feature.
# For more details see official documentation on the Flexiwan Multi-Link.


add_vpp_plugin(fwapp
  SOURCES
#  fwapp_api.c
#  fwapp_itf_attach.c
  fwapp_tap.c
  fwapp_main.c

#  API_FILES
#  fwapp.api

#  INSTALL_HEADERS
#  fwapp_all_api_h.h
#  fwapp_msg_enum.h
)
