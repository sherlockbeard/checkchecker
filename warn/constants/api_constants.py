#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# This file maps the integer values with the constant names for several android classes

MediaRecorder_AudioSource =  {
                                0x0: 'DEFAULT',
                                0x1: 'MIC',
                                0x2: 'VOICE_UPLINK',
                                0x3: 'VOICE_DOWNLINK',
                                0x4: 'VOICE_CALL',
                                0x5: 'CAMCORDER',
                                0x6: 'VOICE_RECOGNITION',
                                0x7: 'VOICE_COMMUNICATION',
                                0x8: 'REMOTE_SUBMIX',
                                0x9: 'UNPROCESSED'
                             }

MediaRecorder_VideoSource =  {
                                0x0: 'DEFAULT',
                                0x1: 'CAMERA',
                                0x2: 'SURFACE'
                             }

PackageManager_PackageInfo = {
                                0x1:            'GET_ACTIVITIES',
                                0x4000:         'GET_CONFIGURATIONS',
                                0x200:          'MATCH_DISABLED_COMPONENTS',
                                0x100:          'GET_GIDS',
                                0x10:           'GET_INSTRUMENTATION',
                                0x20:           'GET_INTENT_FILTERS',
                                0x80:           'GET_META_DATA',
                                0x1000:         'GET_PERMISSIONS',
                                0x8:            'GET_PROVIDERS',
                                0x2:            'GET_RECEIVERS',
                                0x40:           'GET_RESOLVED_FILTER',
                                0x4:            'GET_SERVICES',
                                0x400:          'GET_SHARED_LIBRARY_FILES',
                                0x40:           'GET_SIGNATURES',
                                0x08000000:     'GET_SIGNING_CERTIFICATES',
                                0x2000:         'MATCH_UNINSTALLED_PACKAGES',
                                0x800:          'GET_URI_PERMISSION_PATTERNS',
                                0x00008000:     'MATCH_DISABLED_UNTIL_USED_COMPONENTS',
                                0x00100000:     'MATCH_SYSTEM_ONLY'
                            }