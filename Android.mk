################################################################
# Sample Android repo Makefile, used to test arm on the Tegra K1
################################################################

cpuminer-src := $(call my-dir)

LOCAL_PATH := $(cpuminer-src)
include $(CLEAR_VARS)

LOCAL_MODULE=cpuminer-jansson
LOCAL_MODULE_TAGS=optional

define all-c-files-under
$(patsubst ./%,%, \
  $(shell cd $(LOCAL_PATH) ; \
          find -L $(1) -name "*.c" -and -not -name ".*") \
 )
endef

LOCAL_SRC_FILES := $(call all-c-files-under,compat/jansson)
LOCAL_C_INCLUDES := $(cpuminer-src)/compat/jansson

include $(BUILD_STATIC_LIBRARY)

################################################################


LOCAL_PATH := $(cpuminer-src)
include $(CLEAR_VARS)

LOCAL_MODULE=cpuminer
LOCAL_MODULE_TAGS=optional
LOCAL_MODULE_CLASS := UTILITY_EXECUTABLES
LOCAL_MODULE_PATH := $(PRODUCT_OUT)/utilities
LOCAL_MODULE_STEM := $(LOCAL_MODULE)

LOCAL_C_INCLUDES := $(cpuminer-src)/compat/bionic \
  $(cpuminer-src)/compat/jansson \
  $(TARGET_OUT_INTERMEDIATES)/include/libcurl \
  external/openssl/include \

LOCAL_CFLAGS := -std=c99 -Wno-pointer-sign -Wno-missing-field-initializers \
  -Wno-unused-parameter #-DNOASM
LOCAL_CFLAGS += -DVERSION=\"1.3\"

sph_files:=$(call all-c-files-under,sha3)

LOCAL_SRC_FILES=\
  cpu-miner.c util.c \
  api.c sysinfos.c \
  $(call all-c-files-under,algo) \
  $(filter-out sha3/md_helper.c,$(sph_files)) \
  $(call all-c-files-under,crypto) \
  $(call all-c-files-under,lyra2) \
  asm/sha2-$(TARGET_ARCH).S \
  asm/scrypt-$(TARGET_ARCH).S \
  asm/neoscrypt_asm.S

LOCAL_STATIC_LIBRARIES := libm cpuminer-jansson
LOCAL_STATIC_LIBRARIES += libz libcrypto_static
LOCAL_STATIC_LIBRARIES += libssl_static

# Require curl config changes and an addional
# module definition in external/curl(_static?)
#LOCAL_FORCE_STATIC_EXECUTABLE := true

ifeq ($(LOCAL_FORCE_STATIC_EXECUTABLE),true)
LOCAL_CFLAGS += -DCURL_STATICLIB # -DHTTP_ONLY
LOCAL_STATIC_LIBRARIES += libcurl_static libc
else
LOCAL_SHARED_LIBRARIES := libssl libcrypto
LOCAL_SHARED_LIBRARIES += libcurl
#LOCAL_STATIC_LIBRARIES += libcurl_static
endif

include $(BUILD_EXECUTABLE)

