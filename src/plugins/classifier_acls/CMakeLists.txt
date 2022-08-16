# Copyright (c) 2022 FlexiWAN
#
# List of features made for FlexiWAN (denoted by FLEXIWAN_FEATURE flag):
#  - acl_based_classification: Feature to provide traffic classification using
#  ACL plugin. Matching ACLs provide the service class and importance
#  attribute. The classification result is marked in the packet and can be
#  made use of in other functions like scheduling, policing, marking etc.
#
# This Makefile is added by the Flexiwan feature - acl_based_classification -
# to compile classifier_acls plugin
#

add_vpp_plugin(classifier_acls
  SOURCES
  classifier_acls.c
  node.c
  classifier_acls.h
  inlines.h

  MULTIARCH_SOURCES
  node.c

  API_FILES
  classifier_acls.api

  API_TEST_SOURCES
  classifier_acls_test.c
)
