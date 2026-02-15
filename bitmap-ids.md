# Bitmap IDs Reference

Date: 2026-02-15

## Conventions

- `Code-confirmed`: ID seen in disassembly/decompilation immediate value usage.
- `User-confirmed`: ID provided from asset/manual knowledge.
- `Inferred`: consistent mapping but not yet fully code-traced.

## Core UI Screens

| Bitmap ID | Meaning | Status | Evidence |
|---:|---|---|---|
| 6000 | City screen window background | User-confirmed | user note |
| 6001 | Unskilled workers icon | User-confirmed | user note |
| 6008 | Sick workers icon | User-confirmed | user note |
| 6013 | Total workforce icon | User-confirmed | user note |
| 9453 | Icon/button for opening city screen | User-confirmed | user note |

## Production Dialog / Building UI

| Bitmap ID | Meaning | Status | Evidence |
|---:|---|---|---|
| 9244 | Upgrade building button icon | User-confirmed | user note |
| 9250+ | Production dialog backgrounds | User-confirmed | user note |
| 7000-7058 | City-screen clickable building images | User-confirmed | user note |
| 7058 | Highest university upgrade image | User-confirmed | user note |
| 7300+ | Building images while upgrading (alternate state) | User-confirmed | user note |

## University UI

| Bitmap ID | Meaning | Status | Evidence |
|---:|---|---|---|
| 9900 | University background | Code-confirmed + User-confirmed | `push 0x26ac` @ `0x00474bd9` (`0x26AC`=9900) |
| 9920 | Miner recruit icon | Code-confirmed + User-confirmed | `push 0x26c0` @ `0x0047603f` |
| 9921 | Miner icon (selected/clicked) | User-confirmed | user note |
| 9922 | Prospector recruit icon | Code-confirmed + User-confirmed | `push 0x26c2` @ `0x00476156` |
| 9924 | Farmer recruit icon | Code-confirmed + User-confirmed | `push 0x26c4` @ `0x00476862` |
| 9926 | Forester recruit icon | Code-confirmed + User-confirmed | `push 0x26c6` @ `0x00476f6c` |
| 9928 | Engineer recruit icon | Code-confirmed + User-confirmed | `push 0x26c8` @ `0x00477ac1` |
| 9930 | Rancher recruit icon | Code-confirmed + User-confirmed | `push 0x26ca` @ `0x00478195` |
| 9936 | Driller recruit icon | Code-confirmed + User-confirmed | `push 0x26d0` @ `0x00477b4b` |

## Commodity Icons (700-722)

| Bitmap ID | Commodity | Status |
|---:|---|---|
| 700 | Cotton | User-confirmed |
| 701 | Wool | User-confirmed (from icon sheet context) |
| 702 | Timber | User-confirmed (from icon sheet context) |
| 703 | Coal | User-confirmed |
| 704 | Iron | User-confirmed |
| 705 | Horses | User-confirmed (from icon sheet context) |
| 706 | Oil | User-confirmed (from icon sheet context) |
| 707 | Canned food | User-confirmed |
| 708 | Fabric | User-confirmed |
| 709 | Lumber planks | User-confirmed (from icon sheet context) |
| 710 | Paper/documents | User-confirmed (from icon sheet context) |
| 711 | Steel | User-confirmed |
| 712 | Arms/munitions crate | User-confirmed (from icon sheet context) |
| 713 | Clothing | User-confirmed |
| 714 | Furniture | User-confirmed |
| 715 | Tools | User-confirmed |
| 716 | Cannon/artillery item | User-confirmed (from icon sheet context) |
| 717 | Grain | User-confirmed (from icon sheet context) |
| 718 | Fruit | User-confirmed |
| 719 | Fish | User-confirmed |
| 720 | Cattle | User-confirmed |
| 721 | Diamonds/gems | User-confirmed |
| 722 | Gold | User-confirmed |

## Map Tiles / Strategic Map

| Bitmap ID | Meaning | Status | Source |
|---:|---|---|---|
| 10000 | Plains (base terrain) | User-confirmed | user note |
| 10001 | Woods | User-confirmed | user note |
| 10002 | Hills | User-confirmed | user note |
| 10003 | Mountains | User-confirmed | user note |
| 10004 | Swamp | User-confirmed | user note |
| 10005 | Ocean | User-confirmed | user note |
| 10006 | Desert | User-confirmed | user note |
| 10007 | Farm | User-confirmed | user note |
| 10008 | Cotton plantation | User-confirmed | user note |
| 10009 | Open range (cattle) | User-confirmed | user note |
| 10015 | Orchard | User-confirmed | user note |
| 10016 | Forest | User-confirmed | user note |
| 10028-10029 | Fertile hills (sheep) | User-confirmed | user note |
| 10042-10047 | Railway | User-confirmed | user note |
| 10048-10079 | Rivers | User-confirmed | user note |
| 10080-10085 | Railway being built/planned | User-confirmed | user note |
| 10086-10093 | River source/variant tiles | User-confirmed | user note |
| 10104 | Minor nation town | User-confirmed | user note |
| 10105 | Minor nation capital | User-confirmed | user note |

## Civilian Map Sprites / Animation

| Bitmap ID | Meaning | Status | Source |
|---:|---|---|---|
| 400-408 | Civilian map icons | User-confirmed | user note |
| 409-417 | Civilian selected icon set | User-confirmed | user note |
| 418-426 | Civilian icons (no orders) | User-confirmed | user note |
| 14000-14041 | Civilians working animations | User-confirmed | user note |

## Technology Icons

| Bitmap ID | Meaning | Status | Source |
|---:|---|---|---|
| 2305-2360 | Technology icons set (part 1) | User-confirmed | user note |
| 2373-2400 | Technology icons set (part 2) | User-confirmed | user note |

## Town / Depot / Port Strategic Icons

| Bitmap ID | Meaning | Status | Source |
|---:|---|---|---|
| 550 | Major nation capital | User-confirmed | user note |
| 551 | Major nation town (expansion states family) | User-confirmed | user note |
| 553 | Major nation town (expansion states family) | User-confirmed | user note |
| 554 | Train depot (connected) | User-confirmed | user note |
| 555 | Train depot (unconnected) | User-confirmed | user note |
| 556 | Depot + port (connected) | User-confirmed | user note |
| 557 | Port alone (connected) | User-confirmed | user note |
| 578 | Port unconnected | User-confirmed | user note |
| 579 | Depot + port (unconnected) | User-confirmed | user note |
