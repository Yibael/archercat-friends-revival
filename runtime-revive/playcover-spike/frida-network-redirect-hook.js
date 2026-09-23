(function () {
'use strict';

const hookState = globalThis.__archerCatNetworkRedirectHookState ||
  (globalThis.__archerCatNetworkRedirectHookState = {});

if (hookState.installed) {
  const alreadyLoaded = Object.assign({
    t: new Date().toISOString(),
    kind: 'network_redirect_hook_already_loaded',
    pid: Process.id,
    arch: Process.arch,
    platform: Process.platform,
    alreadyLoaded: true
  }, hookState.readyPayload || {
    status: 'error',
    criticalHooks: {}
  });
  console.log(JSON.stringify(alreadyLoaded));
  if (typeof send === 'function') {
    send(Object.assign({}, alreadyLoaded, { kind: 'network_redirect_hook_ready' }));
  }
  return;
}
hookState.installed = true;
hookState.ready = false;

const retainedBlocks = [];
const retainedNativeCallbacks = [];
const fdTargets = {};
const capturePorts = { 80: true, 443: true, 3000: true, 3001: true };
const hostRedirects = {
  'api.acfserver.net': '127.0.0.1'
};
const portRedirects = {
  3000: 3001
};
const trackedJsonObjects = {};
const trackedJsonTtlMs = 30000;
let trackedJsonLookupCount = 0;
const trackedJsonLookupMax = 500;
let jsonParseLogCount = 0;
const jsonParseLogMax = 300;
const activePostResponseRequestTypesByThread = {};
let verboseJsonLookupUntil = 0;
let verboseJsonLookupCount = 0;
const verboseJsonLookupMax = 800;
let mallocFunction = null;
let getenvFunction = null;
const staticImageBaseArm64 = ptr('0x100000000');
const archerCatArm64Targets = {
  httpPerformRequest: '0x1002d554c',
  httpHeaderCallback: '0x1002d6378',
  httpBodyCallback: '0x1002d63ec',
  postResponseProcess: '0x1002d6468',
  requestEncrypt: '0x1002f0e58',
  responseDecrypt: '0x1002f0f74',
  jsonParseIntoObject: '0x10029acfc',
  jsonObjectLookup: '0x10029a8c4',
  setRemotePublicKey: '0x1002d4c14',
  dialogBuilder: '0x1002fcaa0',
  dialogCloseCallback: '0x1002fcf84',
  postStatusHandler: '0x1002c0df0',
  postStatusCallback: '0x1002c0190',
  postStatusCallbackVtableCallsite: '0x1002c01c8',
  postStatusSuccessCallback: '0x1002c01f4',
  messageCallbackRegister: '0x1002c1a74',
  messageSummon: '0x10007623c',
  messageDialogShow: '0x1002ab4c0',
  profileMapClearListParser: '0x100291ab4',
  profileEventClearListParser: '0x100291eb0',
  profileSkillListParser: '0x100292250',
  profileItemListParser: '0x100292788',
  profileIngredientListParser: '0x100292c48',
  profileStorageItemListParser: '0x100293110',
  profilePortraitListParser: '0x100293b1c',
  profileInviteListParser: '0x100293ecc',
  profileUseFriendListParser: '0x10029432c',
  profilePresentTicketListParser: '0x100294778',
  profilePresentFishListParser: '0x100294bc4',
  profilePresentFriendshipListParser: '0x100295010',
  profileClassInfoParser: '0x100293518',
  profileDungeonListParser: '0x100295b44'
};
const suppressInvalidDataVersionDialogs = false;
const profileEmptyPayload = 'vroAAA';
const profileBase64Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const supportedProfileFixtureNames = Object.freeze({
  baseline: true,
  'event-902': true,
  'event-903': true,
  'event-904': true,
  'event-905': true,
  'event-914': true,
  'training-just-unlocked': true,
  'kingdom-just-unlocked': true,
  'kingdom-quest-ready': true,
  'inventory-type10-item-ready': true,
  'inventory-type1-bow-ready': true,
  'inventory-type2-armor-ready': true,
  'ingredient-id0-count1-readonly': true,
  'inventory-type19-hat-ready': true,
  'inventory-type20-boots-ready': true,
  'inventory-type4-ring-ready': true,
  'inventory-type12-spirit-ready': true,
  'shop-type10-item-ready': true,
  'ordinary-all': true,
  'calendar-day1-available': true,
  'calendar-day2-with-day1-readonly': true,
  'calendar-claimed-today-suppressed': true,
  'raid-49': true,
  'raid-50': true,
  'raid-populated': true,
  'dungeon-before': true,
  'dungeon-cleared': true,
  'dungeon-all-groups': true,
  'world-story-hard': true,
  'world-zone-a': true,
  'world-zones-bcd': true,
  'world-all-cleared': true,
  'story-map1-stage1-clear': true,
  'story-map1-stage4-clear': true,
  'training-missile-ready': true,
  'training-barrier-ready': true,
  'training-powershot-state-flag': true,
  'training-powershot-ready': true,
  'training-multishot-ready': true,
  'training-lightningshot-ready': true,
  'training-iceshot-ready': true,
  'training-poisonshot-ready': true,
  'training-cannonshot-ready': true,
  'training-thunderstormshot-ready': true,
  'training-blizzardshot-ready': true,
  'training-poisoncloudshot-ready': true,
  'shortcut-all-learned': true,
  'all-local': true
});
const worldMapCaptureFixtureNames = Object.freeze({
  'world-story-hard': true,
  'world-zone-a': true,
  'world-zones-bcd': true,
  'world-all-cleared': true,
  'story-map1-stage1-clear': true,
  'story-map1-stage4-clear': true
});
const supportedHookModes = Object.freeze({
  full: true,
  light: true,
  navigation: true
});

function encodeBase64Unpadded(bytes) {
  let result = '';
  for (let index = 0; index < bytes.length; index += 3) {
    const hasSecond = index + 1 < bytes.length;
    const hasThird = index + 2 < bytes.length;
    const first = bytes[index];
    const second = hasSecond ? bytes[index + 1] : 0;
    const third = hasThird ? bytes[index + 2] : 0;
    const packed = (first << 16) | (second << 8) | third;
    result += profileBase64Alphabet[(packed >>> 18) & 0x3f];
    result += profileBase64Alphabet[(packed >>> 12) & 0x3f];
    if (hasSecond) result += profileBase64Alphabet[(packed >>> 6) & 0x3f];
    if (hasThird) result += profileBase64Alphabet[packed & 0x3f];
  }
  return result;
}

function encodeProfileRecords(recordBytes, version) {
  if (recordBytes.length === 0) return '';
  const profileVersion = version === undefined ? 0 : version;
  if (!Number.isInteger(profileVersion) || profileVersion < 0 || profileVersion > 0xffff) {
    throw new Error(`Invalid profile record version: ${profileVersion}`);
  }
  return encodeBase64Unpadded([
    0xbe,
    0xba,
    profileVersion & 0xff,
    (profileVersion >>> 8) & 0xff
  ].concat(recordBytes));
}

function encodeEventClearList(eventIds) {
  const recordBytes = [];
  for (const eventId of eventIds) {
    if (!Number.isInteger(eventId) || eventId < 0 || eventId > 0xffffff) {
      throw new Error(`Invalid profile event ID: ${eventId}`);
    }
    recordBytes.push(eventId & 0xff, (eventId >>> 8) & 0xff, (eventId >>> 16) & 0xff, 1);
  }
  return encodeProfileRecords(recordBytes);
}

function encodeMapClearList(mapClearTuples) {
  const recordBytes = [];
  for (const tuple of mapClearTuples) {
    if (!Array.isArray(tuple) || tuple.length !== 3) {
      throw new Error(`Invalid map-clear tuple: ${JSON.stringify(tuple)}`);
    }
    const [map, zone, stage] = tuple;
    if (
      !Number.isInteger(map) || map < 0 || map > 0xffff ||
      !Number.isInteger(zone) || zone < 0 || zone > 0xff ||
      !Number.isInteger(stage) || stage < 0 || stage > 0xff
    ) {
      throw new Error(`Invalid map-clear tuple: ${JSON.stringify(tuple)}`);
    }
    recordBytes.push(map & 0xff, (map >>> 8) & 0xff, zone, stage);
  }
  return encodeProfileRecords(recordBytes);
}

const ingredientCapacities = Object.freeze([
  50, 50, 50, 100, 200, 200, 200, 200, 200, 50, 50, 50,
  30, 30, 30, 30, 30, 50, 50, 50, 200, 200, 50
]);

function encodeIngredientList(ingredientRecords) {
  if (ingredientRecords.length === 0) return '';
  if (ingredientRecords.length > 0xffff) {
    throw new Error(`Too many ingredient records: ${ingredientRecords.length}`);
  }
  const recordBytes = [
    ingredientRecords.length & 0xff,
    (ingredientRecords.length >>> 8) & 0xff
  ];
  for (const record of ingredientRecords) {
    if (
      record === null ||
      typeof record !== 'object' ||
      Array.isArray(record) ||
      Object.keys(record).sort().join(',') !== 'ingredientId,quantity'
    ) {
      throw new Error(`Invalid ingredient record: ${JSON.stringify(record)}`);
    }
    const { ingredientId, quantity } = record;
    if (
      !Number.isInteger(ingredientId) ||
      ingredientId < 0 ||
      ingredientId >= ingredientCapacities.length ||
      (ingredientId >= 12 && ingredientId <= 16)
    ) {
      throw new Error(`Unsupported ingredient ID: ${ingredientId}`);
    }
    if (
      !Number.isInteger(quantity) ||
      quantity <= 0 ||
      quantity > ingredientCapacities[ingredientId]
    ) {
      throw new Error(`Invalid ingredient quantity for ID ${ingredientId}: ${quantity}`);
    }
    recordBytes.push(
      ingredientId & 0xff,
      (ingredientId >>> 8) & 0xff,
      quantity & 0xff,
      (quantity >>> 8) & 0xff
    );
  }
  return encodeProfileRecords(recordBytes, 111);
}

function writeUnsignedBitsLsbFirst(bits, value, width) {
  for (let bit = 0; bit < width; bit += 1) bits.push((value >>> bit) & 1);
}

function packBitsLsbFirst(bits) {
  return Array.from(
    { length: Math.ceil(bits.length / 8) },
    (_, byteIndex) => bits
      .slice(byteIndex * 8, byteIndex * 8 + 8)
      .reduce((value, bit, index) => value | (bit << index), 0)
  );
}

function encodeItemListVersion0(itemRecords) {
  const payloadBytes = [];
  for (const record of itemRecords) {
    if (record === null || typeof record !== 'object' || Array.isArray(record)) {
      throw new Error(`Invalid item record: ${JSON.stringify(record)}`);
    }
    const {
      recordId,
      factoryParam3Bits,
      factoryParam5Bits,
      itemType,
      stateByte,
      equippedSlot
    } = record;
    const keys = Object.keys(record).sort().join(',');
    const commonKeys = 'equippedSlot,factoryParam3Bits,factoryParam5Bits,itemType,recordId,stateByte';
    const type1Keys =
      'commonByte,equippedSlot,factoryParam3Bits,factoryParam5Bits,itemType,recordId,stateByte,type1Field10,type1Field4';
    const type2Keys =
      'commonByte,equippedSlot,factoryParam3Bits,factoryParam5Bits,itemType,recordId,stateByte,type2Field10A,type2Field10B';
    const type4Keys =
      'commonByte,equippedSlot,factoryParam3Bits,factoryParam5Bits,itemType,nestedCount,nestedMode,recordId,stateByte,type4Field10A,type4Field10B,type4Field10C';
    const type12Keys =
      'commonByte,equippedSlot,factoryParam3Bits,factoryParam5Bits,itemType,nestedCount,nestedMode,recordId,stateByte,type12Field10A,type12Field10B,type12Field10C';
    if (
      (itemType === 10 && keys !== commonKeys) ||
      (itemType === 1 && keys !== type1Keys) ||
      (itemType === 2 && keys !== type2Keys) ||
      (itemType === 4 && keys !== type4Keys) ||
      (itemType === 12 && keys !== type12Keys)
    ) {
      throw new Error(`Invalid item record fields: ${JSON.stringify(record)}`);
    }
    if (itemType !== 1 && itemType !== 2 && itemType !== 4 && itemType !== 10 && itemType !== 12) {
      throw new Error(`Unsupported minimal item type: ${itemType}`);
    }
    if (!Number.isInteger(recordId) || recordId < 0 || recordId > 0xffffffff) {
      throw new Error(`Invalid item record ID: ${recordId}`);
    }
    if (!Number.isInteger(factoryParam3Bits) || factoryParam3Bits < 0 || factoryParam3Bits > 7) {
      throw new Error(`Invalid item 3-bit factory parameter: ${factoryParam3Bits}`);
    }
    if (!Number.isInteger(factoryParam5Bits)) {
      throw new Error(`Invalid item 5-bit factory parameter: ${factoryParam5Bits}`);
    }
    if (itemType === 10 && (factoryParam5Bits < 0 || factoryParam5Bits > 3)) {
      throw new Error(`Invalid type-10 item 5-bit factory parameter: ${factoryParam5Bits}`);
    }
    if (itemType === 1 && (factoryParam3Bits !== 0 || factoryParam5Bits !== 1)) {
      throw new Error(`Unsupported type-1 bow factory parameters: ${JSON.stringify(record)}`);
    }
    if (itemType === 2 && (factoryParam3Bits !== 0 || factoryParam5Bits !== 1)) {
      throw new Error(`Unsupported type-2 armor factory parameters: ${JSON.stringify(record)}`);
    }
    if (itemType === 4 && (factoryParam3Bits !== 0 || factoryParam5Bits !== 0)) {
      throw new Error(`Unsupported type-4 ring factory parameters: ${JSON.stringify(record)}`);
    }
    if (
      itemType === 12 &&
      (factoryParam3Bits !== 0 || factoryParam5Bits !== 9 || stateByte !== 10)
    ) {
      throw new Error(`Unsupported type-12 Spirit factory parameters: ${JSON.stringify(record)}`);
    }
    if (!Number.isInteger(stateByte) || stateByte < 0 || stateByte > 0xff) {
      throw new Error(`Invalid item state byte: ${stateByte}`);
    }
    if (
      equippedSlot !== null &&
      (!Number.isInteger(equippedSlot) || equippedSlot < 0 || equippedSlot > 6)
    ) {
      throw new Error(`Invalid equipped item slot: ${JSON.stringify(record)}`);
    }
    const allowedEquippedSlots = {
      1: [0],
      2: [1],
      4: [2, 3],
      12: [4]
    };
    if (
      equippedSlot !== null &&
      (!Object.prototype.hasOwnProperty.call(allowedEquippedSlots, itemType) ||
        !allowedEquippedSlots[itemType].includes(equippedSlot))
    ) {
      throw new Error(`Unsupported equipped item type/slot: ${JSON.stringify(record)}`);
    }
    if (
      itemType === 1 &&
      (record.commonByte !== 4 || record.type1Field10 !== 18 || record.type1Field4 !== 1)
    ) {
      throw new Error(`Unsupported type-1 bow derived fields: ${JSON.stringify(record)}`);
    }
    if (
      itemType === 2 &&
      (record.commonByte !== 4 || record.type2Field10A !== 20 || record.type2Field10B !== 15)
    ) {
      throw new Error(`Unsupported type-2 armor derived fields: ${JSON.stringify(record)}`);
    }
    if (
      itemType === 4 &&
      (
        record.commonByte !== 0 ||
        record.type4Field10A !== 0 ||
        record.type4Field10B !== 0 ||
        record.type4Field10C !== 0 ||
        record.nestedMode !== 0 ||
        record.nestedCount !== 0
      )
    ) {
      throw new Error(`Unsupported type-4 ring derived fields: ${JSON.stringify(record)}`);
    }
    if (
      itemType === 12 &&
      (
        record.commonByte !== 0 ||
        record.type12Field10A !== 0 ||
        record.type12Field10B !== 0 ||
        record.type12Field10C !== 0 ||
        record.nestedMode !== 0 ||
        record.nestedCount !== 0
      )
    ) {
      throw new Error(`Unsupported type-12 Spirit derived fields: ${JSON.stringify(record)}`);
    }

    // The version-0 item handler reads each record LSB-first from a signed-byte length prefix.
    const bits = [];
    const writeBits = (value, width) => writeUnsignedBitsLsbFirst(bits, value, width);
    writeBits(recordId, 32);
    writeBits(factoryParam3Bits, 3);
    writeBits(factoryParam5Bits, 5);
    writeBits(itemType, 5);
    writeBits(stateByte, 8);
    writeBits(equippedSlot === null ? 0 : 1, 1);
    if (equippedSlot !== null) writeBits(equippedSlot, 3);
    writeBits(0, 1);
    writeBits(
      itemType === 1 || itemType === 2 || itemType === 4 || itemType === 12
        ? record.commonByte
        : 0,
      8
    );
    if (itemType === 1) {
      writeBits(record.type1Field10, 10);
      writeBits(record.type1Field4, 4);
      writeBits(0, 2);
      writeBits(0, 1);
    } else if (itemType === 2) {
      writeBits(record.type2Field10A, 10);
      writeBits(record.type2Field10B, 10);
      writeBits(0, 2);
      writeBits(0, 1);
    } else if (itemType === 4) {
      writeBits(record.type4Field10A, 10);
      writeBits(record.type4Field10B, 10);
      writeBits(record.type4Field10C, 10);
      writeBits(0, 2);
      writeBits(record.nestedMode, 5);
      writeBits(record.nestedCount, 5);
    } else if (itemType === 12) {
      writeBits(record.type12Field10A, 10);
      writeBits(record.type12Field10B, 10);
      writeBits(record.type12Field10C, 10);
      writeBits(0, 2);
      writeBits(record.nestedMode, 5);
      writeBits(record.nestedCount, 5);
    } else {
      writeBits(0, 2);
      writeBits(0, 5);
      writeBits(0, 5);
    }
    const recordBytes = packBitsLsbFirst(bits);
    if (recordBytes.length > 0x7f) {
      throw new Error(`Item record is too long: ${recordBytes.length}`);
    }
    payloadBytes.push(recordBytes.length, ...recordBytes);
  }
  return encodeProfileRecords(payloadBytes);
}

function encodeItemListVersion111(itemRecords) {
  const payloadBytes = [];
  const seenRecordIds = new Set();
  for (const record of itemRecords) {
    if (record === null || typeof record !== 'object' || Array.isArray(record)) {
      throw new Error(`Invalid version-111 item record: ${JSON.stringify(record)}`);
    }
    const { recordId, factoryParam3Bits, factoryParam6Bits, itemType, stateByte } = record;
    const commonKeys = [
      'commonByte',
      'commonField32',
      'commonField4A',
      'commonField4B',
      'factoryParam3Bits',
      'factoryParam6Bits',
      'itemType',
      'recordId',
      'stateByte'
    ];
    const expectedKeys = itemType === 19
      ? commonKeys.concat([
        'type19Field10A',
        'type19Field10B',
        'type19Field10C',
        'type19Field10D'
      ])
      : itemType === 20
        ? commonKeys.concat([
          'type20Field10A',
          'type20Field10B',
          'type20Field10C'
        ])
        : [];
    if (Object.keys(record).sort().join(',') !== expectedKeys.sort().join(',')) {
      throw new Error(`Invalid version-111 item record fields: ${JSON.stringify(record)}`);
    }
    if (!Number.isInteger(recordId) || recordId <= 0 || recordId > 0xffffffff) {
      throw new Error(`Invalid version-111 item record ID: ${recordId}`);
    }
    if (seenRecordIds.has(recordId)) {
      throw new Error(`Duplicate version-111 item record ID: ${recordId}`);
    }
    seenRecordIds.add(recordId);
    if (
      factoryParam3Bits !== 0 ||
      factoryParam6Bits !== 0 ||
      stateByte !== 1 ||
      record.commonByte !== 0 ||
      record.commonField4A !== 1 ||
      record.commonField4B !== 5 ||
      record.commonField32 !== 0
    ) {
      throw new Error(`Unsupported version-111 item common fields: ${JSON.stringify(record)}`);
    }
    const typeFields = itemType === 19
      ? [
        record.type19Field10A,
        record.type19Field10B,
        record.type19Field10C,
        record.type19Field10D
      ]
      : [record.type20Field10A, record.type20Field10B, record.type20Field10C];
    if (typeFields.some((value) => value !== 0)) {
      throw new Error(`Unsupported version-111 item type fields: ${JSON.stringify(record)}`);
    }

    const bits = [];
    const writeBits = (value, width) => writeUnsignedBitsLsbFirst(bits, value, width);
    writeBits(recordId, 32);
    writeBits(factoryParam3Bits, 3);
    writeBits(factoryParam6Bits, 6);
    writeBits(itemType, 5);
    writeBits(stateByte, 8);
    writeBits(0, 1); // collection/reference presence
    writeBits(0, 1); // reserved
    writeBits(record.commonByte, 8);
    for (const value of typeFields) writeBits(value, 10);
    writeBits(0, 2); // nested item gate
    writeBits(0, 1); // common attribute-container presence
    writeBits(0, 4); // four optional 7-bit-field presence flags
    writeBits(0, 6); // six optional 4-bit-field presence flags
    writeBits(record.commonField4A, 4);
    writeBits(record.commonField4B, 4);
    writeBits(record.commonField32, 32);
    writeBits(0, 1); // type-12/type-15 extension presence
    writeBits(0, 1); // shared optional block presence
    writeBits(0, 1); // common Boolean
    const recordBytes = packBitsLsbFirst(bits);
    const expectedLength = itemType === 19 ? 20 : 19;
    if (recordBytes.length !== expectedLength) {
      throw new Error(
        `Invalid version-111 item record length for type ${itemType}: ${recordBytes.length}`
      );
    }
    payloadBytes.push(recordBytes.length, ...recordBytes);
  }
  return encodeProfileRecords(payloadBytes, 111);
}

function encodeItemList(itemRecords) {
  const hasVersion111Record = itemRecords.some((record) =>
    record?.itemType === 19 || record?.itemType === 20
  );
  if (hasVersion111Record) {
    if (!itemRecords.every((record) => record?.itemType === 19 || record?.itemType === 20)) {
      throw new Error('Version-0 and version-111 item records cannot share one profile payload.');
    }
    return encodeItemListVersion111(itemRecords);
  }
  return encodeItemListVersion0(itemRecords);
}

function encodeSkillList(skillRecords) {
  const recordBytes = [];
  for (const record of skillRecords) {
    if (record === null || typeof record !== 'object' || Array.isArray(record)) {
      throw new Error(`Invalid skill record: ${JSON.stringify(record)}`);
    }
    const keys = Object.keys(record).sort();
    if (keys.join(',') !== 'level,skillId,stateFlag') {
      throw new Error(`Invalid skill record fields: ${JSON.stringify(record)}`);
    }
    const { skillId, level, stateFlag } = record;
    if (!Number.isInteger(skillId) || skillId < 0 || skillId > 0xffff) {
      throw new Error(`Invalid skill ID: ${skillId}`);
    }
    if (!Number.isInteger(level) || level < 0 || level > 0xff) {
      throw new Error(`Invalid skill level for ID ${skillId}: ${level}`);
    }
    if (!Number.isInteger(stateFlag) || stateFlag < 0 || stateFlag > 0xff) {
      throw new Error(`Invalid skill state flag for ID ${skillId}: ${stateFlag}`);
    }
    recordBytes.push(skillId & 0xff, (skillId >>> 8) & 0xff, level, stateFlag);
  }
  return encodeProfileRecords(recordBytes);
}

function encodeDungeonList(dungeonRecords) {
  if (dungeonRecords.length === 0) return '';
  if (dungeonRecords.length > 0xffff) {
    throw new Error(`Too many dungeon records: ${dungeonRecords.length}`);
  }

  const recordBytes = [dungeonRecords.length & 0xff, (dungeonRecords.length >>> 8) & 0xff];
  for (const record of dungeonRecords) {
    if (record === null || typeof record !== 'object' || Array.isArray(record)) {
      throw new Error(`Invalid dungeon record: ${JSON.stringify(record)}`);
    }
    const { dungeonKey, booleanState, stageRecords, trailingByte } = record;
    if (!Number.isInteger(dungeonKey) || dungeonKey < 0 || dungeonKey > 0xffff) {
      throw new Error(`Invalid dungeon key: ${dungeonKey}`);
    }
    if (typeof booleanState !== 'boolean') {
      throw new Error(`Invalid dungeon boolean state for key ${dungeonKey}`);
    }
    if (!Array.isArray(stageRecords) || stageRecords.length > 0xffff) {
      throw new Error(`Invalid dungeon stage records for key ${dungeonKey}`);
    }
    if (!Number.isInteger(trailingByte) || trailingByte < 0 || trailingByte > 0xff) {
      throw new Error(`Invalid dungeon trailing byte for key ${dungeonKey}`);
    }

    recordBytes.push(
      dungeonKey & 0xff,
      (dungeonKey >>> 8) & 0xff,
      booleanState ? 1 : 0,
      stageRecords.length & 0xff,
      (stageRecords.length >>> 8) & 0xff
    );
    for (const stageRecord of stageRecords) {
      if (stageRecord === null || typeof stageRecord !== 'object' || Array.isArray(stageRecord)) {
        throw new Error(`Invalid dungeon stage record for key ${dungeonKey}`);
      }
      const { key, value } = stageRecord;
      if (!Number.isInteger(key) || key < 0 || key > 0xffffffff) {
        throw new Error(`Invalid dungeon stage key for dungeon ${dungeonKey}: ${key}`);
      }
      if (!Number.isInteger(value) || value < -0x80 || value > 0x7f) {
        throw new Error(`Invalid dungeon stage value for dungeon ${dungeonKey}: ${value}`);
      }
      recordBytes.push(
        key & 0xff,
        (key >>> 8) & 0xff,
        (key >>> 16) & 0xff,
        (key >>> 24) & 0xff,
        value & 0xff
      );
    }
    recordBytes.push(trailingByte);
  }
  return encodeProfileRecords(recordBytes, 103);
}

function freezeProfileCalendar(name, calendar) {
  if (calendar === null || typeof calendar !== 'object' || Array.isArray(calendar)) {
    throw new Error(`Invalid profile calendar for ${name}: ${JSON.stringify(calendar)}`);
  }
  if (Object.keys(calendar).sort().join(',') !==
      'cumulativeDailyRewardCounter,curTick,lastDailyRewardTick') {
    throw new Error(`Invalid profile calendar fields for ${name}: ${JSON.stringify(calendar)}`);
  }
  const { curTick, lastDailyRewardTick, cumulativeDailyRewardCounter } = calendar;
  if (!Number.isSafeInteger(curTick) || curTick <= 86400001) {
    throw new Error(`Invalid profile calendar curTick for ${name}: ${curTick}`);
  }
  if (
    !Number.isSafeInteger(lastDailyRewardTick) ||
    lastDailyRewardTick < 0 ||
    lastDailyRewardTick > curTick
  ) {
    throw new Error(
      `Invalid profile calendar lastDailyRewardTick for ${name}: ${lastDailyRewardTick}`
    );
  }
  if (
    !Number.isSafeInteger(cumulativeDailyRewardCounter) ||
    cumulativeDailyRewardCounter < 0 ||
    cumulativeDailyRewardCounter > 0xffffffff
  ) {
    throw new Error(
      `Invalid profile calendar cumulativeDailyRewardCounter for ${name}: ${cumulativeDailyRewardCounter}`
    );
  }
  if (
    name === 'calendar-day1-available' &&
    (lastDailyRewardTick !== 0 || cumulativeDailyRewardCounter !== 0)
  ) {
    throw new Error(`Calendar day-1 fixture facts do not match ${name}`);
  }
  if (
    name === 'calendar-day2-with-day1-readonly' &&
    (
      cumulativeDailyRewardCounter !== 1 ||
      curTick - lastDailyRewardTick !== 86400001
    )
  ) {
    throw new Error(`Calendar day-2 fixture facts do not match ${name}`);
  }
  if (
    name === 'calendar-claimed-today-suppressed' &&
    (cumulativeDailyRewardCounter !== 1 || lastDailyRewardTick !== curTick)
  ) {
    throw new Error(`Calendar claimed-today fixture facts do not match ${name}`);
  }
  if (
    name === 'training-just-unlocked' &&
    (cumulativeDailyRewardCounter !== 1 || lastDailyRewardTick !== curTick)
  ) {
    throw new Error(`Training just-unlocked calendar facts do not match ${name}`);
  }
  if (
    name === 'inventory-type10-item-ready' &&
    (cumulativeDailyRewardCounter !== 1 || lastDailyRewardTick !== curTick)
  ) {
    throw new Error(`Type-10 inventory fixture calendar facts do not match ${name}`);
  }
  if (
    (name === 'inventory-type19-hat-ready' || name === 'inventory-type20-boots-ready') &&
    (cumulativeDailyRewardCounter !== 1 || lastDailyRewardTick !== curTick)
  ) {
    throw new Error(`Hat/Boots selector fixture calendar facts do not match ${name}`);
  }
  if (
    name === 'raid-populated' &&
    (cumulativeDailyRewardCounter !== 1 || lastDailyRewardTick !== curTick)
  ) {
    throw new Error(`Raid populated fixture calendar facts do not match ${name}`);
  }
  if (
    Object.prototype.hasOwnProperty.call(worldMapCaptureFixtureNames, name) &&
    (cumulativeDailyRewardCounter !== 1 || lastDailyRewardTick !== curTick)
  ) {
    throw new Error(`World-map fixture calendar facts do not match ${name}`);
  }
  return Object.freeze({
    curTick,
    lastDailyRewardTick,
    cumulativeDailyRewardCounter
  });
}

function defaultProfileCalendar() {
  const curTick = Math.floor(Date.now() / 1000);
  return {
    curTick,
    lastDailyRewardTick: 0,
    cumulativeDailyRewardCounter: 0
  };
}

function isExactStoryStageOneEquippedBow(record) {
  return record !== null &&
    typeof record === 'object' &&
    !Array.isArray(record) &&
    Object.keys(record).sort().join(',') ===
      'commonByte,equippedSlot,factoryParam3Bits,factoryParam5Bits,itemType,recordId,stateByte,type1Field10,type1Field4' &&
    record.recordId === 1 &&
    record.factoryParam3Bits === 0 &&
    record.factoryParam5Bits === 1 &&
    record.itemType === 1 &&
    record.stateByte === 1 &&
    record.equippedSlot === 0 &&
    record.commonByte === 4 &&
    record.type1Field10 === 18 &&
    record.type1Field4 === 1;
}

function createProfileFixture(
  name,
  basePoint,
  mapClearTuples,
  eventIds,
  dungeonRecords,
  skillRecords,
  itemRecords,
  calendar,
  ingredientRecords = []
) {
  if (!Object.prototype.hasOwnProperty.call(supportedProfileFixtureNames, name)) {
    throw new Error(`Unsupported ARCHERCAT_PROFILE_FIXTURE: ${name}`);
  }
  if (!Number.isInteger(basePoint) || basePoint < 0) {
    throw new Error(`Invalid profile basePoint: ${basePoint}`);
  }
  if (name === 'raid-populated' && basePoint !== 12800) {
    throw new Error(`Raid populated fixture requires basePoint 12800: ${basePoint}`);
  }
  const version111FixtureType = name === 'inventory-type19-hat-ready'
    ? 19
    : name === 'inventory-type20-boots-ready'
      ? 20
      : null;
  const version111Records = itemRecords.filter((record) =>
    record?.itemType === 19 || record?.itemType === 20
  );
  if (
    (version111FixtureType !== null && (
      basePoint !== 256 ||
      itemRecords.length !== 1 ||
      version111Records.length !== 1 ||
      version111Records[0].itemType !== version111FixtureType ||
      version111Records[0].recordId !== 1
    )) ||
    (version111FixtureType === null && version111Records.length !== 0)
  ) {
    throw new Error(`Version-111 item records do not match fixture ${name}`);
  }
  const equippedRecords = itemRecords.filter((record) =>
    record !== null &&
    typeof record === 'object' &&
    Object.prototype.hasOwnProperty.call(record, 'equippedSlot') &&
    record.equippedSlot !== null
  );
  if (name === 'story-map1-stage1-clear') {
    if (
      basePoint !== 0 ||
      mapClearTuples.length !== 1 ||
      mapClearTuples[0].length !== 3 ||
      mapClearTuples[0][0] !== 0 ||
      mapClearTuples[0][1] !== 1 ||
      mapClearTuples[0][2] !== 1 ||
      eventIds.length !== 0 ||
      dungeonRecords.length !== 0 ||
      skillRecords.length !== 0 ||
      itemRecords.length !== 1 ||
      equippedRecords.length !== 1 ||
      !isExactStoryStageOneEquippedBow(itemRecords[0]) ||
      ingredientRecords.length !== 0
    ) {
      throw new Error(`Story map-1 stage-1 profile facts do not match fixture ${name}`);
    }
  } else if (equippedRecords.length !== 0) {
    throw new Error(`Equipped item records do not match fixture ${name}`);
  }
  if (
    name === 'training-just-unlocked' && (
      basePoint !== 0 ||
      mapClearTuples.length !== 0 ||
      eventIds.length !== 1 ||
      eventIds[0] !== 902 ||
      dungeonRecords.length !== 0 ||
      skillRecords.length !== 0 ||
      itemRecords.length !== 0 ||
      ingredientRecords.length !== 0
    )
  ) {
    throw new Error(`Training just-unlocked profile facts do not match fixture ${name}`);
  }
  const expectedIngredientRecords = name === 'ingredient-id0-count1-readonly'
    ? [{ ingredientId: 0, quantity: 1 }]
    : [];
  const ingredientRecordsMatch =
    ingredientRecords.length === expectedIngredientRecords.length &&
    ingredientRecords.every((record, index) =>
      record !== null &&
      typeof record === 'object' &&
      !Array.isArray(record) &&
      record.ingredientId === expectedIngredientRecords[index].ingredientId &&
      record.quantity === expectedIngredientRecords[index].quantity
    );
  if (!ingredientRecordsMatch) {
    throw new Error(
      `Ingredient records do not match fixture ${name}: ${JSON.stringify(ingredientRecords)}`
    );
  }
  const frozenMapClearTuples = Object.freeze(
    mapClearTuples.map((tuple) => Object.freeze(tuple.slice()))
  );
  const frozenEventIds = Object.freeze(eventIds.slice());
  const dungeonList = encodeDungeonList(dungeonRecords);
  const frozenDungeonRecords = Object.freeze(dungeonRecords.map((record) => Object.freeze({
    dungeonKey: record.dungeonKey,
    booleanState: record.booleanState,
    stageRecords: Object.freeze(record.stageRecords.map((stageRecord) => Object.freeze({
      key: stageRecord.key,
      value: stageRecord.value
    }))),
    trailingByte: record.trailingByte
  })));
  const skillList = encodeSkillList(skillRecords);
  const frozenSkillRecords = Object.freeze(skillRecords.map((record) => Object.freeze({
    skillId: record.skillId,
    level: record.level,
    stateFlag: record.stateFlag
  })));
  const itemList = encodeItemList(itemRecords);
  const ingredientList = encodeIngredientList(ingredientRecords);
  const frozenCalendar = freezeProfileCalendar(name, calendar);
  const frozenItemRecords = Object.freeze(itemRecords.map((record) => {
    const isVersion111 = record.itemType === 19 || record.itemType === 20;
    const frozenRecord = {
      recordId: record.recordId,
      factoryParam3Bits: record.factoryParam3Bits,
      ...(isVersion111
        ? { factoryParam6Bits: record.factoryParam6Bits }
        : { factoryParam5Bits: record.factoryParam5Bits }),
      itemType: record.itemType,
      stateByte: record.stateByte,
      ...(!isVersion111 ? { equippedSlot: record.equippedSlot } : {})
    };
    if (record.itemType === 1) {
      frozenRecord.commonByte = record.commonByte;
      frozenRecord.type1Field10 = record.type1Field10;
      frozenRecord.type1Field4 = record.type1Field4;
    } else if (record.itemType === 2) {
      frozenRecord.commonByte = record.commonByte;
      frozenRecord.type2Field10A = record.type2Field10A;
      frozenRecord.type2Field10B = record.type2Field10B;
    } else if (record.itemType === 4) {
      frozenRecord.commonByte = record.commonByte;
      frozenRecord.type4Field10A = record.type4Field10A;
      frozenRecord.type4Field10B = record.type4Field10B;
      frozenRecord.type4Field10C = record.type4Field10C;
      frozenRecord.nestedMode = record.nestedMode;
      frozenRecord.nestedCount = record.nestedCount;
    } else if (record.itemType === 12) {
      frozenRecord.commonByte = record.commonByte;
      frozenRecord.type12Field10A = record.type12Field10A;
      frozenRecord.type12Field10B = record.type12Field10B;
      frozenRecord.type12Field10C = record.type12Field10C;
      frozenRecord.nestedMode = record.nestedMode;
      frozenRecord.nestedCount = record.nestedCount;
    } else if (record.itemType === 19) {
      frozenRecord.commonByte = record.commonByte;
      frozenRecord.type19Field10A = record.type19Field10A;
      frozenRecord.type19Field10B = record.type19Field10B;
      frozenRecord.type19Field10C = record.type19Field10C;
      frozenRecord.type19Field10D = record.type19Field10D;
      frozenRecord.commonField4A = record.commonField4A;
      frozenRecord.commonField4B = record.commonField4B;
      frozenRecord.commonField32 = record.commonField32;
    } else if (record.itemType === 20) {
      frozenRecord.commonByte = record.commonByte;
      frozenRecord.type20Field10A = record.type20Field10A;
      frozenRecord.type20Field10B = record.type20Field10B;
      frozenRecord.type20Field10C = record.type20Field10C;
      frozenRecord.commonField4A = record.commonField4A;
      frozenRecord.commonField4B = record.commonField4B;
      frozenRecord.commonField32 = record.commonField32;
    }
    return Object.freeze(frozenRecord);
  }));
  const frozenIngredientRecords = Object.freeze(ingredientRecords.map((record) =>
    Object.freeze({
      ingredientId: record.ingredientId,
      quantity: record.quantity
    })
  ));
  return Object.freeze({
    name,
    basePoint,
    mapClearTuples: frozenMapClearTuples,
    mapClearList: encodeMapClearList(frozenMapClearTuples),
    eventIds: frozenEventIds,
    eventClearList: encodeEventClearList(frozenEventIds),
    dungeonRecords: frozenDungeonRecords,
    dungeonList,
    skillRecords: frozenSkillRecords,
    skillList,
    itemRecords: frozenItemRecords,
    itemList,
    ingredientRecords: frozenIngredientRecords,
    ingredientList,
    calendar: frozenCalendar
  });
}

function profileAuditFacts(fixture) {
  return {
    profileFixture: fixture.name,
    profileBasePoint: fixture.basePoint,
    profileMapClearCount: fixture.mapClearTuples.length,
    profileMapClearTuples: fixture.mapClearTuples,
    profileEventCount: fixture.eventIds.length,
    profileEventIds: fixture.eventIds,
    profileDungeonRecordCount: fixture.dungeonRecords.length,
    profileDungeonRecords: fixture.dungeonRecords,
    profileSkillRecordCount: fixture.skillRecords.length,
    profileSkillRecords: fixture.skillRecords,
    profileItemRecordCount: fixture.itemRecords.length,
    profileItemRecords: fixture.itemRecords,
    profileIngredientRecordCount: fixture.ingredientRecords.length,
    profileIngredientRecords: fixture.ingredientRecords,
    profileCalendar: fixture.calendar
  };
}

let activeProfileFixture = createProfileFixture(
  'baseline', 0, [], [], [], [], [], defaultProfileCalendar()
);
let activeHookMode = 'full';
const suppressedMessageSummons = {
  MsgWnd_InvalidDataVersion_Summon: true
};
const suppressedMessageDialogMarkers = [
  'MsgWnd_InvalidDataVersion',
  '数据版本不匹配',
  '更高版本进行游戏'
];
const interestingJsonKeys = {
  status: true,
  msg: true,
  publicKey: true,
  serverStatus: true,
  maintenance: true,
  notice: true,
  ok: true,
  path: true,
  error: true,
  code: true,
  data: true,
  accessToken: true,
  userId: true,
  user: true,
  nickname: true,
  level: true,
  exp: true,
  coin: true,
  gem: true,
  gold: true,
  items: true,
  itemList: true,
  mailList: true,
  ticketList: true,
  curTick: true,
  lastWeekScoreResetTick: true,
  gameCommonBalanceInfo: true,
  IAP_ProductInfo: true,
  characterStats: true,
  characterClass: true,
  _id: true,
  basePoint: true,
  statLevel: true,
  specialState: true,
  diamond: true,
  numFish: true,
  numFriendship: true,
  mapClearList: true,
  eventClearList: true,
  skillList: true,
  ingredientList: true,
  portraitList: true,
  storageItemList: true,
  classInfo: true,
  dungeonList: true,
  receiveTicket: true,
  receiveFish: true,
  receiveFriendship: true,
  fruitScore: true,
  heroScore: true,
  nestScore: true,
  numPresentItem: true,
  inviteList: true,
  presentTicketList: true,
  presentFishList: true,
  presentFriendshipList: true,
  useFriendList: true,
  lastReceivePotionTick: true,
  lastUpdateFishTick: true,
  lastDailyRewardTick: true,
  cumulativeDailyRewardCounter: true,
  following: true,
  followers: true,
  MaxFishUpdateTick: true,
  MaxFishPresentTick: true,
  MaxTicketPresentTick: true,
  MaxFriendshipPresentTick: true
};

function now() {
  return new Date().toISOString();
}

function log(kind, payload) {
  const entry = Object.assign({ t: now(), kind }, payload || {});
  console.log(JSON.stringify(entry));
  const auditPayload = hostAuditPayload(kind, entry);
  if (auditPayload !== null) {
    notifyHost('network_redirect_audit', auditPayload);
  }
}

function notifyHost(kind, payload) {
  if (typeof send !== 'function') return;
  send(Object.assign({ kind }, payload || {}));
}

function hostAuditPayload(kind, entry) {
  if (kind === 'archercat_response_decrypt_mocked') {
    return {
      t: entry.t,
      eventKind: kind,
      requestType: entry.requestType,
      outputLength: entry.outputLength,
      expectedOutputLength: entry.expectedOutputLength,
      profileFixture: entry.profileFixture,
      profileBasePoint: entry.profileBasePoint,
      profileMapClearCount: entry.profileMapClearCount,
      profileMapClearTuples: entry.profileMapClearTuples,
      profileEventCount: entry.profileEventCount,
      profileEventIds: entry.profileEventIds,
      profileDungeonRecordCount: entry.profileDungeonRecordCount,
      profileDungeonRecords: entry.profileDungeonRecords,
      profileSkillRecordCount: entry.profileSkillRecordCount,
      profileSkillRecords: entry.profileSkillRecords,
      profileItemRecordCount: entry.profileItemRecordCount,
      profileItemRecords: entry.profileItemRecords,
      profileIngredientRecordCount: entry.profileIngredientRecordCount,
      profileIngredientRecords: entry.profileIngredientRecords,
      profileCalendar: entry.profileCalendar,
      containsLocalUserId: entry.containsLocalUserId === true,
      containsLocalGuest: entry.containsLocalGuest === true
    };
  }

  if (kind === 'archercat_request_encrypt' && entry.consumedLocalUserId === true) {
    return {
      t: entry.t,
      eventKind: kind,
      inputLength: entry.input ? entry.input.length : null,
      consumedLocalUserId: true
    };
  }

  return null;
}

function profileSummaryForLog(summary, forceRedact) {
  if (!summary) return summary;
  const text = typeof summary.utf8 === 'string' ? summary.utf8 : summary.ascii;
  const markers = profileMarkers(text);
  if (!forceRedact && !markers.containsLocalUserId && !markers.containsLocalGuest) return summary;
  return {
    pointer: summary.pointer,
    dataPointer: summary.dataPointer,
    length: summary.length,
    captured: summary.captured,
    truncated: summary.truncated,
    redacted: true,
    containsLocalUserId: markers.containsLocalUserId,
    containsLocalGuest: markers.containsLocalGuest
  };
}

function profileMarkers(text) {
  return {
    containsLocalUserId: typeof text === 'string' && text.indexOf('local-user-1') !== -1,
    containsLocalGuest: typeof text === 'string' && text.indexOf('LocalGuest') !== -1
  };
}

function profileTextForLog(text, forceRedact) {
  if (typeof text !== 'string') return text;
  const markers = profileMarkers(text);
  if (!forceRedact && !markers.containsLocalUserId && !markers.containsLocalGuest) return text;
  return {
    length: text.length,
    redacted: true,
    containsLocalUserId: markers.containsLocalUserId,
    containsLocalGuest: markers.containsLocalGuest
  };
}

function pushActivePostResponseRequestType(threadId, requestType) {
  const key = String(threadId);
  const stack = activePostResponseRequestTypesByThread[key] || [];
  stack.push(requestType === undefined ? null : requestType);
  activePostResponseRequestTypesByThread[key] = stack;
}

function currentActivePostResponseRequestType(threadId) {
  const stack = activePostResponseRequestTypesByThread[String(threadId)];
  return stack && stack.length > 0 ? stack[stack.length - 1] : null;
}

function popActivePostResponseRequestType(threadId) {
  const key = String(threadId);
  const stack = activePostResponseRequestTypesByThread[key];
  if (!stack || stack.length === 0) return;
  stack.pop();
  if (stack.length === 0) delete activePostResponseRequestTypesByThread[key];
}

function objcAvailable() {
  return typeof ObjC !== 'undefined' && ObjC.available;
}

function nativeMalloc(size) {
  if (mallocFunction === null) {
    const address = findExport('malloc');
    if (!address) {
      log('malloc_missing', {});
      return NULL;
    }
    mallocFunction = new NativeFunction(address, 'pointer', ['ulong']);
  }
  return mallocFunction(size);
}

function mallocUtf8String(text) {
  const buffer = nativeMalloc(text.length + 1);
  if (ptrIsNull(buffer)) return NULL;
  buffer.writeUtf8String(text);
  return buffer;
}

function iapProduct(type, productId, localizedPrice, amount) {
  const safeAmount = amount || 0;
  const product = {
    type,
    productId,
    id: productId,
    localizedPrice,
    price: 0,
    event: 0,
    presentationType: 0,
    count: safeAmount,
    value: safeAmount
  };

  if (type === 1) {
    product.gold = safeAmount;
  } else if (type === 2) {
    product.gem = safeAmount;
  } else if (productId.indexOf('diamond') >= 0) {
    product.diamond = safeAmount;
  }

  return product;
}

function buildIapProductInfo() {
  const definitions = [
    [1, 'gold_001', '', 1000],
    [1, 'gold_002', '', 2500],
    [1, 'gold_003', '', 6000],
    [1, 'gold_004', '', 13000],
    [1, 'gold_005', '', 40000],
    [1, 'gold_006', '', 70000],
    [2, 'gem_001', '', 10],
    [2, 'gem_002', '', 30],
    [2, 'gem_003', '', 50],
    [2, 'gem_004', '', 110],
    [2, 'gem_005', '', 350],
    [2, 'gem_006', '', 650],
    [0, 'acf_diamond_001', '$0.99', 10],
    [0, 'acf_diamond_002', '$2.99', 33],
    [0, 'acf_diamond_003', '$4.99', 60],
    [0, 'acf_diamond_004', '$9.99', 130],
    [0, 'acf_diamond_005', '$29.99', 450],
    [0, 'acf_diamond_006', '$49.99', 800],
    [3, 'storage_000', ''],
    [3, 'disenchant_000', ''],
    [3, 'recoverattr_000', ''],
    [3, 'changeclass_000', ''],
    [3, 'clearsocket_000', ''],
    [4, 'stone_bow_attackbonus', ''],
    [4, 'stone_bow_attackspeedbonus', ''],
    [4, 'stone_bow_criticalratebonus', ''],
    [4, 'stone_bow_slowratebonus', ''],
    [4, 'stone_bow_piercingratebonus', ''],
    [4, 'stone_bow_powershot', ''],
    [4, 'stone_bow_cannonshot', ''],
    [4, 'stone_bow_multishot', ''],
    [4, 'stone_bow_missileshot', ''],
    [4, 'stone_bow_lightningshot', ''],
    [4, 'stone_bow_thunderstormshot', ''],
    [4, 'stone_bow_iceshot', ''],
    [4, 'stone_bow_blizzardshot', ''],
    [4, 'stone_bow_poisonshot', ''],
    [4, 'stone_bow_poisoncloudshot', ''],
    [4, 'stone_armor_hpbonus', ''],
    [4, 'stone_armor_mpbonus', ''],
    [4, 'stone_armor_slowratebonus', ''],
    [4, 'stone_armor_piercingratebonus', ''],
    [4, 'stone_armor_mpregen', ''],
    [4, 'stone_armor_barrier', ''],
    [4, 'stone_armor_allskillbonus_1', ''],
    [4, 'stone_armor_allskillbonus_2', '']
  ];
  const products = {};
  definitions.forEach((definition) => {
    products[definition[1]] = iapProduct(definition[0], definition[1], definition[2], definition[3]);
  });
  return products;
}

function buildGameCommonBalanceInfo() {
  return {
    IAP_ProductInfo: buildIapProductInfo(),
    MaxFishUpdateTick: 600,
    MaxFishPresentTick: 86400,
    MaxTicketPresentTick: 86400,
    MaxFriendshipPresentTick: 86400,
    MaxInviteFriendTick: 86400,
    MaxUseFriendTick: 86400,
    MaxFishByUpdate: 5,
    InitialMaxFish: 5,
    IncMaxFishPerLevel: 0,
    IncMaxFishCount: 1,
    MaxFishRechargeCost: 1,
    MaxMailCount: 50,
    MaxTicketCount: 5,
    MaxWeekScoreResetTick: 604800,
    MaxReceivePotionTick: 86400,
    IncHeroScoreBySupportFriend: 1,
    IncHeroScoreByWinDuel: 1,
    MaxUpdateHeroScoreTick: 86400,
    MaxPresentItemCount: 50,
    MaxStorageExpandCount: 0,
    MaxStorageItemCountPerExpand: 0,
    PresentItemGemPrice: 0,
    MaxRaidCountPerUser: 0,
    MaxRaidParticipantCount: 0,
    MaxRaidBattleWaitTick: 0,
    MaxRaidRemainTick: 0,
    MaxRaidTime: 0,
    MaxFollowingNum: 50,
    IncFriendshipByGifting: 1,
    FriendshipForExchange: 1,
    MaxFriendship: 100
  };
}

function buildLocalGuestUser(profileFixture) {
  const fixture = profileFixture || activeProfileFixture;
  return {
    _id: 'local-user-1',
    id: 'local-user-1',
    userId: 1,
    nickname: 'LocalGuest',
    basePoint: fixture.basePoint,
    exp: 0,
    statLevel: 1,
    specialState: 0,
    gold: 0,
    gem: 0,
    diamond: 0,
    numFish: 5,
    numFriendship: 0,
    mapClearList: fixture.mapClearList,
    eventClearList: fixture.eventClearList,
    skillList: fixture.skillList,
    itemList: fixture.itemList || profileEmptyPayload,
    ingredientList: fixture.ingredientList,
    portraitList: profileEmptyPayload,
    storageItemList: '',
    classInfo: '',
    dungeonList: fixture.dungeonList,
    receiveTicket: false,
    receiveFish: false,
    receiveFriendship: false,
    fruitScore: 0,
    heroScore: 0,
    nestScore: 0,
    numPresentItem: 0,
    inviteList: '',
    presentTicketList: '',
    presentFishList: '',
    presentFriendshipList: '',
    useFriendList: '',
    lastReceivePotionTick: 0,
    lastUpdateFishTick: 0,
    lastDailyRewardTick: fixture.calendar.lastDailyRewardTick,
    cumulativeDailyRewardCounter: fixture.calendar.cumulativeDailyRewardCounter,
    following: [],
    followers: [],
    mailList: [],
    ticketList: []
  };
}

function buildLoginUserMockResponse(profileFixture) {
  const fixture = profileFixture || activeProfileFixture;
  const user = buildLocalGuestUser(fixture);
  return {
    status: 'ok',
    msg: '',
    accessToken: '_',
    userId: 1,
    nickname: 'LocalGuest',
    dataVersion: 111,
    level: 1,
    exp: 0,
    coin: 0,
    gem: 0,
    gold: 0,
    characterClass: 0,
    characterStats: [],
    items: [],
    itemList: [],
    itemInfo: [],
    friends: [],
    mail: [],
    user,
    mailList: [],
    ticketList: [],
    curTick: fixture.calendar.curTick,
    lastWeekScoreResetTick: fixture.calendar.curTick,
    gameCommonBalanceInfo: buildGameCommonBalanceInfo()
  };
}

function buildCalendarRewardMockResponse() {
  const nowSeconds = Math.floor(Date.now() / 1000);
  return {
    status: 'ok',
    msg: '',
    newLastDailyRewardTick: nowSeconds,
    newCumulativeDailyRewardCounter: 1,
    newGold: 0,
    newGem: 0,
    newDiamond: 1,
    curTick: nowSeconds
  };
}

function buildOkMockResponse() {
  return {
    status: 'ok',
    msg: ''
  };
}

function buildRaidListMockResponse(profileFixture) {
  const fixture = profileFixture || activeProfileFixture;
  if (fixture.name !== 'raid-populated') return null;
  return [{
    creator: 'fixture-other',
    _id: 'fixture-raid-1',
    bossType: 1,
    bossCurHp: 1,
    participantList: []
  }];
}

function mockPlaintextResponseForRequestType(requestType, profileFixture) {
  if (requestType === 85) {
    return {
      status: 'ok',
      msg: '',
      ids: [],
      facebookIds: [],
      kakaoIds: [],
      users: []
    };
  }

  if (requestType === 3 || requestType === 4) {
    return buildLoginUserMockResponse(profileFixture);
  }

  if (requestType === 73) {
    return buildCalendarRewardMockResponse();
  }

  if (requestType === 76) {
    return buildOkMockResponse();
  }

  if (requestType === 57) {
    return buildRaidListMockResponse(profileFixture);
  }

  return null;
}

function ptrIsNull(value) {
  return value === null || value.isNull();
}

function toUtf8(pointerValue) {
  if (ptrIsNull(pointerValue)) return null;
  try {
    return pointerValue.readUtf8String();
  } catch (error) {
    return `<readUtf8String failed: ${error}>`;
  }
}

function addrinfoHints(pointerValue) {
  if (ptrIsNull(pointerValue)) return null;
  try {
    return {
      flags: pointerValue.add(0).readS32(),
      family: pointerValue.add(4).readS32(),
      socktype: pointerValue.add(8).readS32(),
      protocol: pointerValue.add(12).readS32()
    };
  } catch (error) {
    return { error: String(error) };
  }
}

function nsObject(pointerValue) {
  if (!objcAvailable() || ptrIsNull(pointerValue)) return null;
  try {
    return new ObjC.Object(pointerValue);
  } catch (_) {
    return null;
  }
}

function nsString(pointerValue) {
  const obj = nsObject(pointerValue);
  if (obj === null) return null;
  try {
    return obj.toString();
  } catch (error) {
    return `<ObjC toString failed: ${error}>`;
  }
}

function objSummary(pointerValue, maxLength) {
  const obj = nsObject(pointerValue);
  if (obj === null) return null;
  try {
    const text = obj.toString();
    const limit = maxLength || 256;
    return text.length > limit ? `${text.slice(0, limit)}...` : text;
  } catch (error) {
    return `<ObjC summary failed: ${error}>`;
  }
}

function nsDataSummary(pointerValue, maxBytes) {
  const data = nsObject(pointerValue);
  if (data === null) return null;

  try {
    const length = Number(data.length());
    if (length === 0) {
      return { length: 0, ascii: '', hex: '' };
    }
    return bufferSummary(data.bytes(), length, maxBytes || 2048);
  } catch (error) {
    return { error: String(error) };
  }
}

function bufferSummary(pointerValue, length, maxBytes) {
  if (ptrIsNull(pointerValue)) return null;
  const safeLength = Math.max(0, Number(length || 0));
  const limit = Math.min(safeLength, maxBytes || 2048);
  let bytes;

  try {
    bytes = new Uint8Array(pointerValue.readByteArray(limit));
  } catch (error) {
    return { length: safeLength, error: String(error) };
  }

  let ascii = '';
  let hex = '';
  for (let i = 0; i < bytes.length; i += 1) {
    const value = bytes[i];
    ascii += value >= 32 && value <= 126 ? String.fromCharCode(value) : '.';
    hex += (value < 16 ? '0' : '') + value.toString(16);
    if (i + 1 < bytes.length) hex += ' ';
  }

  return {
    length: safeLength,
    captured: limit,
    ascii,
    hex,
    truncated: safeLength > limit
  };
}

function readUtf8Summary(pointerValue, length, maxBytes) {
  if (ptrIsNull(pointerValue)) return null;
  const safeLength = Math.max(0, Number(length || 0));
  const limit = Math.min(safeLength, maxBytes || 8192);

  if (limit === 0) {
    return {
      utf8: '',
      utf8Captured: 0,
      utf8Truncated: safeLength > limit
    };
  }

  try {
    return {
      utf8: pointerValue.readUtf8String(limit),
      utf8Captured: limit,
      utf8Truncated: safeLength > limit
    };
  } catch (error) {
    return {
      utf8Error: String(error),
      utf8Captured: limit,
      utf8Truncated: safeLength > limit
    };
  }
}

function readGnuStdString(pointerValue, maxBytes) {
  if (ptrIsNull(pointerValue)) return null;

  try {
    const dataPointer = pointerValue.readPointer();
    if (ptrIsNull(dataPointer)) return { length: 0, ascii: '', hex: '' };

    const length = Number(dataPointer.add(-0x18).readU64());
    if (!Number.isFinite(length) || length < 0 || length > 1024 * 1024) {
      return {
        pointer: String(pointerValue),
        dataPointer: String(dataPointer),
        error: `implausible std::string length: ${length}`
      };
    }

    return Object.assign({
      pointer: String(pointerValue),
      dataPointer: String(dataPointer)
    }, bufferSummary(dataPointer, length, maxBytes || 8192), readUtf8Summary(dataPointer, length, maxBytes || 8192));
  } catch (error) {
    return {
      pointer: String(pointerValue),
      error: String(error)
    };
  }
}

function readPointerRangeSummary(startPointer, endPointer, maxBytes) {
  if (ptrIsNull(startPointer) || ptrIsNull(endPointer)) return null;

  try {
    const length = Number(endPointer.sub(startPointer));
    if (!Number.isFinite(length) || length <= 0 || length > 1024 * 1024) {
      return {
        start: String(startPointer),
        end: String(endPointer),
        error: `implausible pointer range length: ${length}`
      };
    }
    return Object.assign({
      start: String(startPointer),
      end: String(endPointer)
    }, bufferSummary(startPointer, length, maxBytes || 8192));
  } catch (error) {
    return {
      start: String(startPointer),
      end: String(endPointer),
      error: String(error)
    };
  }
}

function readOutBuffer(outputPointerSlot, outputLengthSlot, maxBytes) {
  const out = {
    pointerSlot: String(outputPointerSlot),
    lengthSlot: String(outputLengthSlot)
  };

  try {
    const dataPointer = outputPointerSlot.readPointer();
    const length = outputLengthSlot.readS32();
    out.dataPointer = String(dataPointer);
    out.length = length;
    out.data = bufferSummary(dataPointer, length, maxBytes || 8192);
  } catch (error) {
    out.error = String(error);
  }

  return out;
}

function readArcherCatResponse(pointerValue) {
  if (ptrIsNull(pointerValue)) return null;

  const out = { pointer: String(pointerValue) };
  try {
    const requestPointer = pointerValue.readPointer();
    out.requestPointer = String(requestPointer);
    if (!ptrIsNull(requestPointer)) {
      out.requestType = requestPointer.readS32();
    }
  } catch (error) {
    out.requestError = String(error);
  }

  try {
    out.bodyStart = String(pointerValue.add(0x8).readPointer());
    out.bodyEnd = String(pointerValue.add(0x10).readPointer());
    out.body = readPointerRangeSummary(pointerValue.add(0x8).readPointer(), pointerValue.add(0x10).readPointer(), 8192);
  } catch (error) {
    out.bodyError = String(error);
  }

  try {
    out.status = pointerValue.add(0x38).readS32();
  } catch (error) {
    out.statusError = String(error);
  }

  return out;
}

function readArcherCatResponseRequestType(pointerValue) {
  if (ptrIsNull(pointerValue)) return null;
  try {
    const requestPointer = pointerValue.readPointer();
    return ptrIsNull(requestPointer) ? null : requestPointer.readS32();
  } catch (_) {
    return null;
  }
}

function readArcherCatRequest(pointerValue) {
  if (ptrIsNull(pointerValue)) return null;

  const out = { pointer: String(pointerValue) };
  try { out.requestType = pointerValue.readS32(); } catch (error) { out.requestTypeError = String(error); }
  try { out.stringArg = readGnuStdString(pointerValue.add(0x8), 2048); } catch (_) {}
  return out;
}

function addressInfo(pointerValue) {
  if (ptrIsNull(pointerValue)) return { pointer: String(pointerValue), null: true };

  const out = { pointer: String(pointerValue) };
  try {
    const range = Process.findRangeByAddress(pointerValue);
    if (range) {
      out.range = {
        base: String(range.base),
        size: range.size,
        protection: range.protection,
        file: range.file ? range.file.path : null
      };
    }
  } catch (error) {
    out.rangeError = String(error);
  }

  try {
    const module = Process.findModuleByAddress(pointerValue);
    if (module) {
      out.module = {
        name: module.name,
        base: String(module.base),
        path: module.path
      };
    }
  } catch (_) {}

  return out;
}

function readVtableCallTarget(objectPointer, offset) {
  const out = {
    object: addressInfo(objectPointer),
    offset
  };
  if (ptrIsNull(objectPointer)) return out;

  try {
    const vtable = objectPointer.readPointer();
    out.vtable = addressInfo(vtable);
    out.target = addressInfo(vtable.add(offset).readPointer());
  } catch (error) {
    out.error = String(error);
  }

  return out;
}

function findArcherCatModule() {
  const modules = Process.enumerateModules();
  for (let i = 0; i < modules.length; i += 1) {
    const module = modules[i];
    if (/ArcherCatXFacebook/i.test(module.name) || /ArcherCatXFacebook/i.test(module.path)) {
      return module;
    }
  }
  return modules.length > 0 ? modules[0] : null;
}

function archerCatRuntimeAddress(staticAddress) {
  const module = findArcherCatModule();
  if (module === null) return null;
  return module.base.add(ptr(staticAddress).sub(staticImageBaseArm64));
}

function hookArcherCatArm64Function(label, staticAddress, callbacks) {
  if (Process.arch !== 'arm64') {
    log('archercat_hook_skipped', { label, staticAddress, reason: `unsupported arch ${Process.arch}` });
    return false;
  }

  const address = archerCatRuntimeAddress(staticAddress);
  const module = findArcherCatModule();
  if (address === null || module === null) {
    log('archercat_hook_missing_module', { label, staticAddress });
    return false;
  }

  try {
    Interceptor.attach(address, callbacks);
    log('hooked_archercat_arm64', {
      label,
      staticAddress,
      runtimeAddress: String(address),
      module: {
        name: module.name,
        base: String(module.base),
        path: module.path
      }
    });
    return true;
  } catch (error) {
    log('archercat_hook_error', { label, staticAddress, runtimeAddress: String(address), error: String(error) });
    return false;
  }
}

function replaceArcherCatArm64Function(label, staticAddress, returnType, argTypes, replacementFactory) {
  if (Process.arch !== 'arm64') {
    log('archercat_replace_skipped', { label, staticAddress, reason: `unsupported arch ${Process.arch}` });
    return;
  }

  const address = archerCatRuntimeAddress(staticAddress);
  const module = findArcherCatModule();
  if (address === null || module === null) {
    log('archercat_replace_missing_module', { label, staticAddress });
    return;
  }

  try {
    const original = new NativeFunction(address, returnType, argTypes);
    const replacement = new NativeCallback(replacementFactory(original), returnType, argTypes);
    retainedNativeCallbacks.push(replacement);
    Interceptor.replace(address, replacement);
    log('replaced_archercat_arm64', {
      label,
      staticAddress,
      runtimeAddress: String(address),
      module: {
        name: module.name,
        base: String(module.base),
        path: module.path
      }
    });
  } catch (error) {
    log('archercat_replace_error', { label, staticAddress, runtimeAddress: String(address), error: String(error) });
  }
}

function replaceMessageSummon(staticAddress) {
  replaceArcherCatArm64Function('message_summon', staticAddress, 'pointer', ['pointer'], (original) => {
    return function (namePointer) {
      const name = toUtf8(namePointer);
      const suppressed = suppressInvalidDataVersionDialogs &&
        (!!suppressedMessageSummons[name] || shouldSuppressMessageDialog(name));
      log('archercat_message_summon', {
        namePointer: String(namePointer),
        name,
        suppressed
      });
      if (suppressed) return NULL;
      return original(namePointer);
    };
  });
}

function shouldSuppressMessageDialog(message) {
  if (!message) return false;
  return suppressedMessageDialogMarkers.some((marker) => message.indexOf(marker) >= 0);
}

function replaceMessageDialogShow(staticAddress) {
  replaceArcherCatArm64Function('message_dialog_show_invalid_data_version_guard', staticAddress, 'void', ['pointer', 'pointer'], (original) => {
    return function (manager, messageStringPointer) {
      const message = readGnuStdString(messageStringPointer, 2048);
      const text = message && typeof message.utf8 === 'string' ? message.utf8 : null;
      const suppressed = suppressInvalidDataVersionDialogs && shouldSuppressMessageDialog(text);
      log('archercat_message_dialog_show', {
        manager: String(manager),
        message,
        suppressed
      });
      if (suppressed) return;
      return original(manager, messageStringPointer);
    };
  });
}

function hookProfileParser(fieldName, staticAddress) {
  hookArcherCatArm64Function(`profile_${fieldName}_parser`, staticAddress, {
    onEnter(args) {
      this.owner = args[0];
      this.input = readGnuStdString(args[1], 2048);
      log('archercat_profile_parser_enter', {
        fieldName,
        owner: String(this.owner),
        input: profileSummaryForLog(this.input, true)
      });
    },
    onLeave(retval) {
      const originalRetval = retval.toInt32();
      log('archercat_profile_parser_leave', {
        fieldName,
        originalRetval,
        forcedRetval: originalRetval,
        forced: false
      });
    }
  });
}

function keepScriptAlive() {
  setInterval(function () {
    // Keep the Frida script alive when launched from a non-interactive wrapper.
  }, 1000);
}

function readSockaddrPort(pointerValue) {
  const portBE = pointerValue.add(2).readU16();
  return ((portBE & 0xff) << 8) | ((portBE >> 8) & 0xff);
}

function writeSockaddrPort(pointerValue, port) {
  pointerValue.add(2).writeU8((port >> 8) & 0xff);
  pointerValue.add(3).writeU8(port & 0xff);
}

function writeSockaddrIpv4(pointerValue, host) {
  const parts = host.split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) =>
    !Number.isInteger(part) || part < 0 || part > 0xff)) {
    throw new Error(`Invalid IPv4 redirect host: ${host}`);
  }
  parts.forEach((part, index) => pointerValue.add(4 + index).writeU8(part));
}

function sockaddr(pointerValue) {
  if (ptrIsNull(pointerValue)) return null;

  try {
    const family = pointerValue.add(1).readU8();

    if (family === 2) {
      const port = readSockaddrPort(pointerValue);
      const b0 = pointerValue.add(4).readU8();
      const b1 = pointerValue.add(5).readU8();
      const b2 = pointerValue.add(6).readU8();
      const b3 = pointerValue.add(7).readU8();
      return { family: 'AF_INET', host: `${b0}.${b1}.${b2}.${b3}`, port };
    }

    if (family === 30) {
      const port = readSockaddrPort(pointerValue);
      const parts = [];
      for (let i = 0; i < 16; i += 2) {
        const hi = pointerValue.add(8 + i).readU8();
        const lo = pointerValue.add(8 + i + 1).readU8();
        parts.push(((hi << 8) | lo).toString(16));
      }
      return { family: 'AF_INET6', host: parts.join(':'), port };
    }

    return { family };
  } catch (error) {
    return { error: String(error) };
  }
}

function rewriteSockaddr(pointerValue, before) {
  if (!before || !before.port || !portRedirects[before.port]) return before;

  const redirectedPort = portRedirects[before.port];
  const redirectedHost = before.family === 'AF_INET' ? hostRedirects['api.acfserver.net'] : null;
  try {
    if (redirectedHost) writeSockaddrIpv4(pointerValue, redirectedHost);
    writeSockaddrPort(pointerValue, redirectedPort);
    const after = sockaddr(pointerValue);
    log(redirectedHost && before.host !== redirectedHost
      ? 'socket_endpoint_rewrite'
      : 'socket_port_rewrite', { before, after });
    return after;
  } catch (error) {
    log('socket_endpoint_rewrite_error', {
      before,
      redirectedHost,
      redirectedPort,
      error: String(error)
    });
    return before;
  }
}

function interestingFd(fd) {
  const target = fdTargets[fd];
  return target && capturePorts[target.port];
}

function dataLooksUseful(summary) {
  if (!summary || !summary.ascii) return false;
  return textLooksUseful(summary.ascii);
}

function textLooksUseful(text) {
  if (!text) return false;
  return /HTTP|GET |POST |PUT |DELETE|api\.acfserver|archercat-local-mock|GetServerStatus|ExchangeKey|LoginUser|CreateUser|publicKey|packetCount|dataVersion|serverStatus|maintenance|server|login|status|msg|error/i.test(text);
}

function nsStringSummary(pointerValue, maxLength) {
  const text = nsString(pointerValue);
  if (text === null) return null;
  const limit = maxLength || 4096;
  return {
    length: text.length,
    captured: Math.min(text.length, limit),
    ascii: text.length > limit ? `${text.slice(0, limit)}...` : text,
    truncated: text.length > limit
  };
}

function objectClassName(pointerValue) {
  const obj = nsObject(pointerValue);
  if (obj === null) return null;
  try {
    return obj.$className;
  } catch (_) {
    return null;
  }
}

function outNSError(pointerValue) {
  if (ptrIsNull(pointerValue)) return null;
  try {
    return nsString(pointerValue.readPointer());
  } catch (_) {
    return null;
  }
}

function trackJsonObject(pointerValue, reason, sensitive) {
  if (!objcAvailable() || ptrIsNull(pointerValue)) return;
  const className = objectClassName(pointerValue);
  if (!className) return;
  trackedJsonObjects[String(pointerValue)] = {
    reason,
    className,
    sensitive: sensitive === true,
    until: Date.now() + trackedJsonTtlMs
  };
}

function trackedJsonInfo(pointerValue) {
  if (ptrIsNull(pointerValue)) return null;
  const key = String(pointerValue);
  const info = trackedJsonObjects[key];
  if (!info) return null;
  if (Date.now() > info.until) {
    delete trackedJsonObjects[key];
    return null;
  }
  return info;
}

function logJsonParse(api, inputSummary, resultPointer, errorOutPointer) {
  const resultText = objSummary(resultPointer, 4096);
  const errorText = outNSError(errorOutPointer);
  const useful = dataLooksUseful(inputSummary) || textLooksUseful(resultText) || textLooksUseful(errorText);
  const inputText = inputSummary && (
    typeof inputSummary.utf8 === 'string' ? inputSummary.utf8 : inputSummary.ascii
  );
  const inputMarkers = profileMarkers(inputText);
  const resultMarkers = profileMarkers(resultText);
  const sensitive = inputMarkers.containsLocalUserId || inputMarkers.containsLocalGuest ||
    resultMarkers.containsLocalUserId || resultMarkers.containsLocalGuest;

  if (useful) {
    trackJsonObject(resultPointer, api, sensitive);
  }

  if (!useful || jsonParseLogCount >= jsonParseLogMax) return;
  jsonParseLogCount += 1;
  log('json_parse', {
    api,
    input: profileSummaryForLog(inputSummary, sensitive),
    result: {
      className: objectClassName(resultPointer),
      text: profileTextForLog(resultText, sensitive)
    },
    error: profileTextForLog(errorText)
  });
}

function hookExport(name, callbacks) {
  const address = findExport(name);
  if (!address) {
    log('hook_missing', { name });
    return false;
  }
  try {
    Interceptor.attach(address, callbacks);
    log('hooked_export', { name, address: String(address) });
    return true;
  } catch (error) {
    log('hook_error', { name, address: String(address), error: String(error) });
    return false;
  }
}

function findExport(name) {
  const resolvers = [];
  if (typeof Module !== 'undefined' && typeof Module.findGlobalExportByName === 'function') {
    resolvers.push(() => Module.findGlobalExportByName(name));
  }
  if (typeof Module !== 'undefined' && typeof Module.getGlobalExportByName === 'function') {
    resolvers.push(() => Module.getGlobalExportByName(name));
  }
  if (typeof Module !== 'undefined' && typeof Module.findExportByName === 'function') {
    resolvers.push(() => Module.findExportByName(null, name));
  }
  for (const resolve of resolvers) {
    try {
      const address = resolve();
      if (address) return address;
    } catch (_) {}
  }

  if (typeof Process === 'undefined' || typeof Process.enumerateModules !== 'function') {
    return null;
  }
  const matches = new Map();
  for (const candidate of Process.enumerateModules()) {
    let exports;
    try {
      if (typeof candidate.enumerateExports === 'function') {
        exports = candidate.enumerateExports();
      } else if (typeof Module !== 'undefined' && typeof Module.enumerateExports === 'function') {
        exports = Module.enumerateExports(candidate.name);
      } else {
        continue;
      }
    } catch (_) {
      continue;
    }
    for (const entry of exports) {
      if (
        entry &&
        entry.name === name &&
        (!entry.type || entry.type === 'function') &&
        entry.address &&
        (typeof entry.address.isNull !== 'function' || !entry.address.isNull())
      ) {
        matches.set(String(entry.address), entry.address);
      }
    }
  }
  return matches.size === 1 ? matches.values().next().value : null;
}

function readTargetEnvironmentValue(name) {
  if (getenvFunction === null) {
    const address = findExport('getenv');
    if (!address) return null;
    getenvFunction = new NativeFunction(address, 'pointer', ['pointer']);
  }
  const value = getenvFunction(Memory.allocUtf8String(name));
  return ptrIsNull(value) ? null : value.readUtf8String();
}

function resolveProfileFixture() {
  const requested = readTargetEnvironmentValue('ARCHERCAT_PROFILE_FIXTURE');
  if (requested === null) {
    return createProfileFixture(
      'baseline', 0, [], [], [], [], [], defaultProfileCalendar()
    );
  }
  const basePointValue = readTargetEnvironmentValue('ARCHERCAT_PROFILE_BASE_POINT');
  const mapClearTuplesValue = readTargetEnvironmentValue(
    'ARCHERCAT_PROFILE_MAP_CLEAR_TUPLES'
  );
  const eventIdsValue = readTargetEnvironmentValue('ARCHERCAT_PROFILE_EVENT_IDS');
  const dungeonRecordsValue = readTargetEnvironmentValue('ARCHERCAT_PROFILE_DUNGEON_RECORDS');
  const skillRecordsValue = readTargetEnvironmentValue('ARCHERCAT_PROFILE_SKILL_RECORDS');
  const itemRecordsValue = readTargetEnvironmentValue('ARCHERCAT_PROFILE_ITEM_RECORDS');
  const ingredientRecordsValue = readTargetEnvironmentValue(
    'ARCHERCAT_PROFILE_INGREDIENT_RECORDS'
  );
  const calendarValue = readTargetEnvironmentValue('ARCHERCAT_PROFILE_CALENDAR');
  if (
    basePointValue === null ||
    mapClearTuplesValue === null ||
    eventIdsValue === null ||
    dungeonRecordsValue === null ||
    skillRecordsValue === null ||
    itemRecordsValue === null ||
    ingredientRecordsValue === null ||
    calendarValue === null
  ) {
    throw new Error(`Incomplete profile fixture environment for ${requested}`);
  }

  let mapClearTuples;
  let eventIds;
  let dungeonRecords;
  let skillRecords;
  let itemRecords;
  let ingredientRecords;
  let calendar;
  try {
    mapClearTuples = JSON.parse(mapClearTuplesValue);
    eventIds = JSON.parse(eventIdsValue);
    dungeonRecords = JSON.parse(dungeonRecordsValue);
    skillRecords = JSON.parse(skillRecordsValue);
    itemRecords = JSON.parse(itemRecordsValue);
    ingredientRecords = JSON.parse(ingredientRecordsValue);
    calendar = JSON.parse(calendarValue);
  } catch (error) {
    throw new Error(`Invalid profile fixture JSON for ${requested}: ${error}`);
  }
  if (
    !Array.isArray(mapClearTuples) ||
    !Array.isArray(eventIds) ||
    !Array.isArray(dungeonRecords) ||
    !Array.isArray(skillRecords) ||
    !Array.isArray(itemRecords) ||
    !Array.isArray(ingredientRecords)
  ) {
    throw new Error(`Profile fixture arrays are invalid for ${requested}`);
  }
  return createProfileFixture(
    requested,
    Number(basePointValue),
    mapClearTuples,
    eventIds,
    dungeonRecords,
    skillRecords,
    itemRecords,
    calendar,
    ingredientRecords
  );
}

function resolveHookMode() {
  const requested = readTargetEnvironmentValue('ARCHERCAT_HOOK_MODE') || 'full';
  if (!Object.prototype.hasOwnProperty.call(supportedHookModes, requested)) {
    throw new Error(`Unsupported ARCHERCAT_HOOK_MODE: ${requested}`);
  }
  return requested;
}

function isFacebookHost(host) {
  if (!host) return false;
  const normalized = host.toLowerCase().replace(/\.$/, '');
  return normalized === 'facebook.com' || normalized.endsWith('.facebook.com');
}

function hookGetaddrinfo() {
  return hookExport('getaddrinfo', {
    onEnter(args) {
      this.node = toUtf8(args[0]);
      this.service = toUtf8(args[1]);
      this.hints = addrinfoHints(args[2]);
      this.rewrite = null;
      this.serviceRewrite = null;

      if (this.node && hostRedirects[this.node]) {
        this.rewrite = hostRedirects[this.node];
        this.rewritePtr = Memory.allocUtf8String(this.rewrite);
        args[0] = this.rewritePtr;
        this.context.x0 = this.rewritePtr;
        log('dns_rewrite', {
          originalNode: this.node,
          replacementNode: this.rewrite,
          service: this.service || ''
        });
      }

      if (isFacebookHost(this.node) && !this.service) {
        this.serviceRewrite = '443';
        this.serviceRewritePtr = Memory.allocUtf8String(this.serviceRewrite);
        args[1] = this.serviceRewritePtr;
        this.context.x1 = this.serviceRewritePtr;
        log('dns_service_rewrite', {
          node: this.node,
          hints: this.hints,
          originalService: this.service,
          replacementService: this.serviceRewrite
        });
      }
    },
    onLeave(retval) {
      const service = this.service || '';
      const node = this.node || '';
      if (service === '3000' || service === '3001' || /acfserver|cravemob|facebook|kakao/i.test(node)) {
        log('getaddrinfo', {
          node,
          rewrittenNode: this.rewrite,
          rewrittenService: this.serviceRewrite,
          service,
          hints: this.hints,
          retval: retval.toInt32()
        });
      }
    }
  });
}

function hookSockets(captureTraffic) {
  const installed = {};

  installed.connect = hookExport('connect', {
    onEnter(args) {
      this.fd = args[0].toInt32();
      this.remote = sockaddr(args[1]);
      this.remote = rewriteSockaddr(args[1], this.remote);
      if (this.remote && this.remote.port) {
        fdTargets[this.fd] = this.remote;
      }
    },
    onLeave(retval) {
      if (this.remote && capturePorts[this.remote.port]) {
        log('socket_connect', {
          fd: this.fd,
          remote: this.remote,
          retval: retval.toInt32()
        });
      }
    }
  });

  if (!captureTraffic) return installed;

  ['send', 'write'].forEach((name) => {
    installed[name] = hookExport(name, {
      onEnter(args) {
        this.name = name;
        this.fd = args[0].toInt32();
        this.buffer = args[1];
        this.length = args[2].toInt32();
        this.capture = interestingFd(this.fd);
        this.summary = this.capture ? bufferSummary(this.buffer, this.length, 4096) : null;
        if (!this.capture) {
          const candidate = bufferSummary(this.buffer, Math.min(this.length, 512), 512);
          if (dataLooksUseful(candidate)) {
            this.summary = candidate;
            this.capture = true;
          }
        }
      },
      onLeave(retval) {
        if (!this.capture) return;
        log('socket_write', {
          api: this.name,
          fd: this.fd,
          remote: fdTargets[this.fd] || null,
          retval: retval.toInt32(),
          data: this.summary
        });
      }
    });
  });

  ['recv', 'read'].forEach((name) => {
    installed[name] = hookExport(name, {
      onEnter(args) {
        this.name = name;
        this.fd = args[0].toInt32();
        this.buffer = args[1];
        this.capture = interestingFd(this.fd);
      },
      onLeave(retval) {
        const length = retval.toInt32();
        if (length <= 0) return;
        const summary = bufferSummary(this.buffer, length, 4096);
        if (!this.capture && !dataLooksUseful(summary)) return;
        log('socket_read', {
          api: this.name,
          fd: this.fd,
          remote: fdTargets[this.fd] || null,
          retval: length,
          data: summary
        });
      }
    });
  });

  installed.close = hookExport('close', {
    onEnter(args) {
      this.fd = args[0].toInt32();
      this.remote = fdTargets[this.fd];
    },
    onLeave(retval) {
      if (this.remote && capturePorts[this.remote.port]) {
        log('socket_close', {
          fd: this.fd,
          remote: this.remote,
          retval: retval.toInt32()
        });
      }
      delete fdTargets[this.fd];
    }
  });

  return installed;
}

function describeRequest(pointerValue) {
  const request = nsObject(pointerValue);
  if (request === null) return null;

  const out = {};
  try { out.url = request.URL().absoluteString().toString(); } catch (_) {}
  try { out.method = request.HTTPMethod().toString(); } catch (_) {}
  try { out.headers = request.allHTTPHeaderFields().toString(); } catch (_) {}
  try { out.body = profileSummaryForLog(nsDataSummary(request.HTTPBody(), 4096)); } catch (_) {}
  return out;
}

function describeResponse(pointerValue) {
  const response = nsObject(pointerValue);
  if (response === null) return null;

  const out = {};
  try { out.className = response.$className; } catch (_) {}
  try { out.url = response.URL().absoluteString().toString(); } catch (_) {}
  try {
    if (ObjC.classes.NSHTTPURLResponse && response.isKindOfClass_(ObjC.classes.NSHTTPURLResponse)) {
      out.statusCode = Number(response.statusCode());
      out.headers = response.allHeaderFields().toString();
    }
  } catch (_) {}
  return out;
}

function wrapCompletionBlock(blockPointer, name, requestInfo, argOrder) {
  if (ptrIsNull(blockPointer)) return;

  try {
    const block = new ObjC.Block(blockPointer);
    const original = block.implementation;

    block.implementation = function () {
      const args = Array.prototype.slice.call(arguments);
      const dataArg = args[argOrder.data];
      const responseArg = args[argOrder.response];
      const errorArg = args[argOrder.error];

      log('objc_response', {
        api: name,
        request: requestInfo,
        response: describeResponse(responseArg),
        data: profileSummaryForLog(nsDataSummary(dataArg, 8192)),
        error: profileTextForLog(nsString(errorArg))
      });

      return original.apply(this, args);
    };

    retainedBlocks.push(block);
  } catch (error) {
    log('objc_block_wrap_error', {
      api: name,
      error: String(error)
    });
  }
}

function hookObjCMethod(className, selector, callback) {
  if (!objcAvailable()) return;
  const cls = ObjC.classes[className];
  if (!cls || !cls[selector]) {
    log('objc_hook_missing', { className, selector });
    return;
  }
  Interceptor.attach(cls[selector].implementation, callback);
  log('hooked_objc', { className, selector });
}

function hookObjCNetworking() {
  if (!objcAvailable()) {
    log('objc_unavailable', {});
    return;
  }

  hookObjCMethod('NSURLSession', '- dataTaskWithRequest:completionHandler:', {
    onEnter(args) {
      const requestInfo = describeRequest(args[2]);
      log('objc_request', { api: 'NSURLSession.dataTaskWithRequest', request: requestInfo });
      wrapCompletionBlock(args[3], 'NSURLSession.dataTaskWithRequest', requestInfo, {
        data: 0,
        response: 1,
        error: 2
      });
    }
  });

  hookObjCMethod('NSURLSession', '- dataTaskWithURL:completionHandler:', {
    onEnter(args) {
      const url = nsString(args[2]);
      const requestInfo = { url };
      log('objc_request', { api: 'NSURLSession.dataTaskWithURL', request: requestInfo });
      wrapCompletionBlock(args[3], 'NSURLSession.dataTaskWithURL', requestInfo, {
        data: 0,
        response: 1,
        error: 2
      });
    }
  });

  hookObjCMethod('NSURLSession', '- uploadTaskWithRequest:fromData:completionHandler:', {
    onEnter(args) {
      const requestInfo = describeRequest(args[2]);
      requestInfo.uploadBody = profileSummaryForLog(nsDataSummary(args[3], 4096));
      log('objc_request', { api: 'NSURLSession.uploadTaskWithRequest', request: requestInfo });
      wrapCompletionBlock(args[4], 'NSURLSession.uploadTaskWithRequest', requestInfo, {
        data: 0,
        response: 1,
        error: 2
      });
    }
  });

  hookObjCMethod('NSURLConnection', '+ sendAsynchronousRequest:queue:completionHandler:', {
    onEnter(args) {
      const requestInfo = describeRequest(args[2]);
      log('objc_request', { api: 'NSURLConnection.sendAsynchronousRequest', request: requestInfo });
      wrapCompletionBlock(args[4], 'NSURLConnection.sendAsynchronousRequest', requestInfo, {
        response: 0,
        data: 1,
        error: 2
      });
    }
  });

  hookObjCMethod('NSURLConnection', '+ sendSynchronousRequest:returningResponse:error:', {
    onEnter(args) {
      this.requestInfo = describeRequest(args[2]);
      this.responseOut = args[3];
      this.errorOut = args[4];
      log('objc_request', { api: 'NSURLConnection.sendSynchronousRequest', request: this.requestInfo });
    },
    onLeave(retval) {
      let response = null;
      let error = null;
      try {
        if (!ptrIsNull(this.responseOut)) response = describeResponse(this.responseOut.readPointer());
      } catch (_) {}
      try {
        if (!ptrIsNull(this.errorOut)) error = nsString(this.errorOut.readPointer());
      } catch (_) {}
      log('objc_response', {
        api: 'NSURLConnection.sendSynchronousRequest',
        request: this.requestInfo,
        response,
        data: profileSummaryForLog(nsDataSummary(retval, 8192)),
        error: profileTextForLog(error)
      });
    }
  });
}

function hookJSONParsers() {
  if (!objcAvailable()) return;

  hookObjCMethod('NSJSONSerialization', '+ JSONObjectWithData:options:error:', {
    onEnter(args) {
      this.input = nsDataSummary(args[2], 8192);
      this.errorOut = args[4];
    },
    onLeave(retval) {
      logJsonParse('NSJSONSerialization.JSONObjectWithData', this.input, retval, this.errorOut);
    }
  });

  hookObjCMethod('JSONDecoder', '- parseJSONData:', {
    onEnter(args) {
      this.input = nsDataSummary(args[2], 8192);
      this.errorOut = NULL;
    },
    onLeave(retval) {
      logJsonParse('JSONDecoder.parseJSONData', this.input, retval, this.errorOut);
    }
  });

  hookObjCMethod('JSONDecoder', '- parseJSONData:error:', {
    onEnter(args) {
      this.input = nsDataSummary(args[2], 8192);
      this.errorOut = args[3];
    },
    onLeave(retval) {
      logJsonParse('JSONDecoder.parseJSONData:error', this.input, retval, this.errorOut);
    }
  });

  hookObjCMethod('JSONDecoder', '- parseUTF8String:length:', {
    onEnter(args) {
      this.input = bufferSummary(args[2], args[3].toInt32(), 8192);
      this.errorOut = NULL;
    },
    onLeave(retval) {
      logJsonParse('JSONDecoder.parseUTF8String:length', this.input, retval, this.errorOut);
    }
  });

  hookObjCMethod('JSONDecoder', '- parseUTF8String:length:error:', {
    onEnter(args) {
      this.input = bufferSummary(args[2], args[3].toInt32(), 8192);
      this.errorOut = args[4];
    },
    onLeave(retval) {
      logJsonParse('JSONDecoder.parseUTF8String:length:error', this.input, retval, this.errorOut);
    }
  });

  [
    '- objectFromJSONString',
    '- objectFromJSONStringWithParseOptions:',
    '- objectFromJSONStringWithParseOptions:error:',
    '- mutableObjectFromJSONString',
    '- mutableObjectFromJSONStringWithParseOptions:',
    '- mutableObjectFromJSONStringWithParseOptions:error:'
  ].forEach((selector) => {
    hookObjCMethod('NSString', selector, {
      onEnter(args) {
        this.input = nsStringSummary(args[0], 8192);
        this.errorOut = selector.endsWith(':error:') ? args[3] : NULL;
      },
      onLeave(retval) {
        logJsonParse(`NSString.${selector}`, this.input, retval, this.errorOut);
      }
    });
  });

  [
    '- objectFromJSONData',
    '- objectFromJSONDataWithParseOptions:',
    '- objectFromJSONDataWithParseOptions:error:',
    '- mutableObjectFromJSONData',
    '- mutableObjectFromJSONDataWithParseOptions:',
    '- mutableObjectFromJSONDataWithParseOptions:error:'
  ].forEach((selector) => {
    hookObjCMethod('NSData', selector, {
      onEnter(args) {
        this.input = nsDataSummary(args[0], 8192);
        this.errorOut = selector.endsWith(':error:') ? args[3] : NULL;
      },
      onLeave(retval) {
        logJsonParse(`NSData.${selector}`, this.input, retval, this.errorOut);
      }
    });
  });
}

function hookTrackedCollectionLookups() {
  if (!objcAvailable()) return;

  const classNames = [
    'NSDictionary',
    'NSMutableDictionary',
    '__NSDictionaryI',
    '__NSDictionaryM',
    '__NSSingleEntryDictionaryI',
    '__NSCFDictionary',
    'JKDictionary'
  ];
  const selectors = ['- objectForKey:', '- objectForKeyedSubscript:'];
  const seen = {};

  classNames.forEach((className) => {
    const cls = ObjC.classes[className];
    if (!cls) return;

    selectors.forEach((selector) => {
      if (!cls[selector]) return;
      const address = cls[selector].implementation;
      const key = `${selector}:${address}`;
      if (seen[key]) return;
      seen[key] = true;

      Interceptor.attach(address, {
        onEnter(args) {
          const trackedInfo = trackedJsonInfo(args[0]);
          if (!trackedInfo || trackedJsonLookupCount >= trackedJsonLookupMax) return;
          this.shouldLog = true;
          this.className = className;
          this.selector = selector;
          this.trackedInfo = trackedInfo;
          this.key = objSummary(args[2], 160);
        },
        onLeave(retval) {
          if (!this.shouldLog) return;
          trackedJsonLookupCount += 1;
          trackJsonObject(retval, `${this.trackedInfo.reason}.${this.key}`, this.trackedInfo.sensitive);
          log('json_object_lookup', {
            className: this.className,
            selector: this.selector,
            jsonSource: this.trackedInfo,
            key: this.key,
            value: {
              className: objectClassName(retval),
              text: profileTextForLog(objSummary(retval, 512), this.trackedInfo.sensitive)
            }
          });
        }
      });
      log('hooked_objc', { className, selector });
    });
  });

  const arrayClassNames = [
    'NSArray',
    'NSMutableArray',
    '__NSArrayI',
    '__NSArrayM',
    '__NSArray0',
    '__NSSingleObjectArrayI',
    '__NSCFArray',
    'JKArray'
  ];
  const arraySelectors = ['- objectAtIndex:', '- objectAtIndexedSubscript:'];

  arrayClassNames.forEach((className) => {
    const cls = ObjC.classes[className];
    if (!cls) return;

    arraySelectors.forEach((selector) => {
      if (!cls[selector]) return;
      const address = cls[selector].implementation;
      const key = `${selector}:${address}`;
      if (seen[key]) return;
      seen[key] = true;

      Interceptor.attach(address, {
        onEnter(args) {
          const trackedInfo = trackedJsonInfo(args[0]);
          if (!trackedInfo || trackedJsonLookupCount >= trackedJsonLookupMax) return;
          this.shouldLog = true;
          this.className = className;
          this.selector = selector;
          this.trackedInfo = trackedInfo;
          this.index = args[2].toInt32();
        },
        onLeave(retval) {
          if (!this.shouldLog) return;
          trackedJsonLookupCount += 1;
          trackJsonObject(retval, `${this.trackedInfo.reason}[${this.index}]`, this.trackedInfo.sensitive);
          log('json_array_lookup', {
            className: this.className,
            selector: this.selector,
            jsonSource: this.trackedInfo,
            index: this.index,
            value: {
              className: objectClassName(retval),
              text: profileTextForLog(objSummary(retval, 512), this.trackedInfo.sensitive)
            }
          });
        }
      });
      log('hooked_objc', { className, selector });
    });
  });
}

function createResponseDecryptCallbacks(
  navigationMode,
  expectedLoginProfileLength,
  profileFixture
) {
  const fixture = profileFixture || activeProfileFixture;
  return {
    onEnter(args) {
      this.key = args[0];
      this.blockSize = Number(args[1]);
      this.input = args[2];
      this.inputLength = args[3].toInt32();
      this.outputPointerSlot = args[4];
      this.outputLengthSlot = args[5];
      this.inputSummary = navigationMode
        ? null
        : bufferSummary(this.input, this.inputLength, 8192);
      this.requestType = currentActivePostResponseRequestType(this.threadId);
    },
    onLeave(retval) {
      const mockResponse = mockPlaintextResponseForRequestType(
        this.requestType,
        fixture
      );
      let mockedPlaintext = null;
      if (mockResponse !== null) {
        const plaintext = JSON.stringify(mockResponse);
        const buffer = mallocUtf8String(plaintext);
        if (!ptrIsNull(buffer)) {
          this.outputPointerSlot.writePointer(buffer);
          this.outputLengthSlot.writeS32(plaintext.length);
          retval.replace(ptr(1));
          verboseJsonLookupUntil = Date.now() + 15000;
          verboseJsonLookupCount = 0;
          mockedPlaintext = plaintext;
          log('archercat_response_decrypt_mocked', Object.assign({
            requestType: this.requestType,
            outputPointer: String(buffer),
            outputLength: plaintext.length,
            expectedOutputLength: expectedLoginProfileLength
          }, profileAuditFacts(fixture), {
            containsLocalUserId: plaintext.indexOf('local-user-1') !== -1,
            containsLocalGuest: plaintext.indexOf('LocalGuest') !== -1
          }));
        }
      }
      if (!navigationMode) {
        log('archercat_response_decrypt', {
          key: String(this.key),
          blockSize: this.blockSize,
          requestType: this.requestType,
          retval: Number(retval),
          input: this.inputSummary,
          output: mockedPlaintext === null
            ? readOutBuffer(this.outputPointerSlot, this.outputLengthSlot, 8192)
            : {
                length: mockedPlaintext.length,
                redacted: true,
                containsLocalUserId: mockedPlaintext.indexOf('local-user-1') !== -1,
                containsLocalGuest: mockedPlaintext.indexOf('LocalGuest') !== -1
              }
        });
      }
    }
  };
}

function hookArcherCatRuntime(
  fullTelemetry,
  navigationMode,
  expectedLoginProfileLength
) {
  const installed = {};

  if (fullTelemetry) {
    installed.httpPerformRequest = hookArcherCatArm64Function('http_perform_request', archerCatArm64Targets.httpPerformRequest, {
      onEnter(args) {
        this.manager = args[0];
        this.request = args[1];
        this.requestInfo = readArcherCatRequest(this.request);
        log('archercat_http_request_begin', {
          manager: String(this.manager),
          request: this.requestInfo
        });
      },
      onLeave(retval) {
        log('archercat_http_request_end', {
          request: this.requestInfo,
          response: readArcherCatResponse(retval)
        });
      }
    });

    hookArcherCatArm64Function('http_header_callback', archerCatArm64Targets.httpHeaderCallback, {
      onEnter(args) {
        const length = args[1].toInt32() * args[2].toInt32();
        this.summary = bufferSummary(args[0], length, 2048);
        this.callbackContext = String(args[3]);
      },
      onLeave(retval) {
        if (!dataLooksUseful(this.summary)) return;
        log('archercat_http_header_callback', {
          context: this.callbackContext,
          retval: Number(retval),
          data: this.summary
        });
      }
    });

    hookArcherCatArm64Function('http_body_callback', archerCatArm64Targets.httpBodyCallback, {
      onEnter(args) {
        const length = args[1].toInt32() * args[2].toInt32();
        this.summary = bufferSummary(args[0], length, 8192);
        this.callbackContext = String(args[3]);
      },
      onLeave(retval) {
        log('archercat_http_body_callback', {
          context: this.callbackContext,
          retval: Number(retval),
          data: this.summary
        });
      }
    });
  }

  installed.postResponseProcess = hookArcherCatArm64Function('post_response_process', archerCatArm64Targets.postResponseProcess, {
    onEnter(args) {
      this.manager = args[0];
      this.response = args[1];
      this.responseInfo = navigationMode ? null : readArcherCatResponse(this.response);
      this.requestType = navigationMode
        ? readArcherCatResponseRequestType(this.response)
        : (this.responseInfo ? this.responseInfo.requestType : null);
      this.postResponseThreadId = this.threadId;
      pushActivePostResponseRequestType(
        this.postResponseThreadId,
        this.requestType
      );
      if (!navigationMode) {
        log('archercat_post_response_enter', {
          manager: String(this.manager),
          response: this.responseInfo
        });
      }
    },
    onLeave() {
      if (!navigationMode) {
        log('archercat_post_response_leave', {
          manager: String(this.manager),
          response: readArcherCatResponse(this.response)
        });
      }
      popActivePostResponseRequestType(this.postResponseThreadId);
    }
  });

  if (!navigationMode) {
    hookArcherCatArm64Function('request_encrypt', archerCatArm64Targets.requestEncrypt, {
      onEnter(args) {
        this.key = args[0];
        this.blockSize = Number(args[1]);
        this.input = args[2];
        this.inputLength = args[3].toInt32();
        this.outputPointerSlot = args[4];
        this.outputLengthSlot = args[5];
        this.inputSummary = bufferSummary(this.input, this.inputLength, 8192);
      },
      onLeave(retval) {
        const inputText = typeof this.inputSummary.utf8 === 'string'
          ? this.inputSummary.utf8
          : this.inputSummary.ascii;
        const consumedLocalUserId = inputText === 'local-user-1';
        log('archercat_request_encrypt', {
          key: String(this.key),
          blockSize: this.blockSize,
          retval: Number(retval),
          input: profileSummaryForLog(this.inputSummary),
          consumedLocalUserId,
          output: readOutBuffer(this.outputPointerSlot, this.outputLengthSlot, 8192)
        });
      }
    });
  }

  installed.responseDecrypt = hookArcherCatArm64Function(
    'response_decrypt',
    archerCatArm64Targets.responseDecrypt,
    createResponseDecryptCallbacks(
      navigationMode,
      expectedLoginProfileLength,
      activeProfileFixture
    )
  );

  if (fullTelemetry) {
    hookArcherCatArm64Function('json_parse_into_object', archerCatArm64Targets.jsonParseIntoObject, {
    onEnter(args) {
      this.target = args[0];
      this.input = readGnuStdString(args[1], 8192);
      if (dataLooksUseful(this.input)) {
        log('archercat_json_parse_enter', {
          target: String(this.target),
          input: profileSummaryForLog(this.input)
        });
      }
    },
    onLeave(retval) {
      if (!dataLooksUseful(this.input)) return;
      log('archercat_json_parse_leave', {
        target: String(this.target),
        retval: String(retval)
      });
    }
  });

  hookArcherCatArm64Function('json_object_lookup', archerCatArm64Targets.jsonObjectLookup, {
    onEnter(args) {
      this.object = args[0];
      this.key = toUtf8(args[1]);
      this.verbose = this.key && Date.now() < verboseJsonLookupUntil &&
        verboseJsonLookupCount < verboseJsonLookupMax;
      this.shouldLog = this.key && (interestingJsonKeys[this.key] || this.verbose);
    },
    onLeave(retval) {
      if (!this.shouldLog) return;
      if (this.verbose && !interestingJsonKeys[this.key]) {
        verboseJsonLookupCount += 1;
      }
      log('archercat_json_object_lookup', {
        object: String(this.object),
        key: this.key,
        valuePointer: String(retval),
        verbose: !!this.verbose
      });
    }
  });

  hookArcherCatArm64Function('set_remote_public_key', archerCatArm64Targets.setRemotePublicKey, {
    onEnter(args) {
      log('archercat_set_remote_public_key', {
        manager: String(args[0]),
        publicKey: readGnuStdString(args[1], 4096)
      });
    }
  });

  hookArcherCatArm64Function('post_status_handler', archerCatArm64Targets.postStatusHandler, {
    onEnter(args) {
      this.manager = args[0];
      this.response = args[1];
      log('archercat_post_status_handler_enter', {
        manager: String(this.manager),
        response: readArcherCatResponse(this.response)
      });
    },
    onLeave() {
      log('archercat_post_status_handler_leave', {
        manager: String(this.manager),
        response: readArcherCatResponse(this.response)
      });
    }
  });

  hookArcherCatArm64Function('message_callback_register', archerCatArm64Targets.messageCallbackRegister, {
    onEnter(args) {
      log('archercat_message_callback_register', {
        owner: String(args[0]),
        callback: addressInfo(args[1]),
        userData: String(args[2]),
        messageObject: readVtableCallTarget(args[3], 0x30)
      });
    }
  });

  replaceMessageSummon(archerCatArm64Targets.messageSummon);
  replaceMessageDialogShow(archerCatArm64Targets.messageDialogShow);

  hookArcherCatArm64Function('dialog_builder', archerCatArm64Targets.dialogBuilder, {
    onEnter(args) {
      log('archercat_dialog_builder_enter', {
        self: readVtableCallTarget(args[0], 0x298)
      });
    },
    onLeave(retval) {
      log('archercat_dialog_builder_leave', {
        result: readVtableCallTarget(retval, 0x298)
      });
    }
  });

  hookArcherCatArm64Function('dialog_close_callback', archerCatArm64Targets.dialogCloseCallback, {
    onEnter(args) {
      log('archercat_dialog_close_callback_enter', {
        self: readVtableCallTarget(args[0], 0x298)
      });
    },
    onLeave() {
      log('archercat_dialog_close_callback_leave', {});
    }
  });

  hookArcherCatArm64Function('post_status_callback', archerCatArm64Targets.postStatusCallback, {
    onEnter(args) {
      log('archercat_post_status_callback_enter', {
        arg0: String(args[0]),
        messageObject: readVtableCallTarget(args[1], 0x30),
        selectedObjectProvider: readVtableCallTarget(args[1], 0x28)
      });
    },
    onLeave(retval) {
      log('archercat_post_status_callback_leave', {
        retval: Number(retval)
      });
    }
  });

  hookArcherCatArm64Function('post_status_callback_vtable_callsite', archerCatArm64Targets.postStatusCallbackVtableCallsite, {
    onEnter() {
      log('archercat_post_status_callback_vtable_callsite', {
        selectedObject: readVtableCallTarget(this.context.x0, 0x2c0)
      });
    }
  });

  hookArcherCatArm64Function('post_status_success_callback', archerCatArm64Targets.postStatusSuccessCallback, {
    onEnter(args) {
      log('archercat_post_status_success_callback_enter', {
        manager: String(args[0]),
        arg1: String(args[1])
      });
    },
    onLeave(retval) {
      log('archercat_post_status_success_callback_leave', {
        retval: Number(retval)
      });
    }
  });

  hookProfileParser('mapClearList', archerCatArm64Targets.profileMapClearListParser);
  hookProfileParser('eventClearList', archerCatArm64Targets.profileEventClearListParser);
  hookProfileParser('skillList', archerCatArm64Targets.profileSkillListParser);
  hookProfileParser('itemList', archerCatArm64Targets.profileItemListParser);
  hookProfileParser('ingredientList', archerCatArm64Targets.profileIngredientListParser);
  hookProfileParser('storageItemList', archerCatArm64Targets.profileStorageItemListParser);
  hookProfileParser('portraitList', archerCatArm64Targets.profilePortraitListParser);
  hookProfileParser('inviteList', archerCatArm64Targets.profileInviteListParser);
  hookProfileParser('useFriendList', archerCatArm64Targets.profileUseFriendListParser);
  hookProfileParser('presentTicketList', archerCatArm64Targets.profilePresentTicketListParser);
  hookProfileParser('presentFishList', archerCatArm64Targets.profilePresentFishListParser);
  hookProfileParser('presentFriendshipList', archerCatArm64Targets.profilePresentFriendshipListParser);
  hookProfileParser('classInfo', archerCatArm64Targets.profileClassInfoParser);
    hookProfileParser('dungeonList', archerCatArm64Targets.profileDungeonListParser);
  }

  return installed;
}

if (globalThis.__archerCatNetworkRedirectHookTestMode === true) {
  globalThis.__archerCatNetworkRedirectHookTestApi = Object.freeze({
    createProfileFixture,
    encodeItemList,
    buildLoginUserMockResponse,
    mockPlaintextResponseForRequestType,
    createResponseDecryptCallbacks,
    profileAuditFacts,
    hostAuditPayload,
    findExport
  });
  hookState.installed = false;
  return;
}

let bootstrapPhase = 'resolve_hook_mode';
try {
  activeHookMode = resolveHookMode();
  bootstrapPhase = 'resolve_profile_fixture';
  activeProfileFixture = resolveProfileFixture();
  bootstrapPhase = 'compute_profile_length';
  const expectedLoginProfileLength = JSON.stringify(buildLoginUserMockResponse()).length;

  log('network_redirect_hook_loaded', {
    pid: Process.id,
    arch: Process.arch,
    platform: Process.platform,
    hostRedirects,
    portRedirects,
    suppressInvalidDataVersionDialogs,
    profileEmptyPayload,
    profileFixture: activeProfileFixture.name,
    profileBasePoint: activeProfileFixture.basePoint,
    profileMapClearTuples: activeProfileFixture.mapClearTuples,
    profileEventIds: activeProfileFixture.eventIds,
    profileDungeonRecords: activeProfileFixture.dungeonRecords,
    profileSkillRecords: activeProfileFixture.skillRecords,
    profileItemRecords: activeProfileFixture.itemRecords,
    profileIngredientRecords: activeProfileFixture.ingredientRecords,
    profileCalendar: activeProfileFixture.calendar,
    hookMode: activeHookMode,
    expectedLoginProfileLength
  });

  bootstrapPhase = 'install_getaddrinfo';
  const getaddrinfoInstalled = hookGetaddrinfo();
  const fullTelemetry = activeHookMode === 'full';
  const navigationMode = activeHookMode === 'navigation';
  bootstrapPhase = 'install_socket_hooks';
  const installedSocketHooks = hookSockets(fullTelemetry);
  if (fullTelemetry) {
    bootstrapPhase = 'install_full_telemetry_hooks';
    hookObjCNetworking();
    hookJSONParsers();
    hookTrackedCollectionLookups();
  }
  bootstrapPhase = 'install_archercat_runtime_hooks';
  const installedRuntimeHooks = hookArcherCatRuntime(
    fullTelemetry,
    navigationMode,
    expectedLoginProfileLength
  );
  const persistentHooks = fullTelemetry
    ? ['full-telemetry']
    : navigationMode
      ? ['getaddrinfo', 'connect', 'post_response_process', 'response_decrypt']
      : ['getaddrinfo', 'connect', 'post_response_process', 'request_encrypt', 'response_decrypt'];
  const criticalHooks = {
    getaddrinfo: getaddrinfoInstalled === true,
    connect: installedSocketHooks.connect === true,
    postResponseProcess: installedRuntimeHooks.postResponseProcess === true,
    responseDecrypt: installedRuntimeHooks.responseDecrypt === true
  };
  const networkReady = Object.keys(criticalHooks).every((name) => criticalHooks[name]);
  const readyPayload = Object.assign({
    status: networkReady ? 'ok' : 'error',
    pid: Process.id,
    arch: Process.arch,
    platform: Process.platform,
    objcAvailable: objcAvailable()
  }, profileAuditFacts(activeProfileFixture), {
    hookMode: activeHookMode,
    persistentHooks,
    expectedLoginProfileLength,
    criticalHooks
  });
  bootstrapPhase = 'publish_ready';
  keepScriptAlive();
  hookState.ready = networkReady;
  hookState.readyPayload = readyPayload;
  log('network_redirect_hook_ready', readyPayload);
  notifyHost('network_redirect_hook_ready', readyPayload);
  if (!networkReady) {
    throw new Error(`Critical network hooks failed: ${JSON.stringify(criticalHooks)}`);
  }
} catch (error) {
  const failure = {
    t: new Date().toISOString(),
    kind: 'network_redirect_hook_bootstrap_error',
    status: 'error',
    phase: bootstrapPhase,
    pid: typeof Process !== 'undefined' ? Process.id : null,
    error: String(error),
    stack: error && typeof error.stack === 'string' ? error.stack : null
  };
  hookState.installed = false;
  hookState.ready = false;
  hookState.readyPayload = failure;
  try { console.log(JSON.stringify(failure)); } catch (_) {}
  try { notifyHost('network_redirect_hook_bootstrap_error', failure); } catch (_) {}
  throw error;
}
})();
