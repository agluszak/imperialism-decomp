#ifndef IMPERIALISM_RUNTIME_COARSE_MAP_ORACLE_H
#define IMPERIALISM_RUNTIME_COARSE_MAP_ORACLE_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeCoarseMapOracle is test-only and must not be included in the production build
#endif

class TMapMaker;
struct json_value_t;
typedef struct json_value_t JSON_Value;

void RuntimeCoarseMapOracleReset(unsigned int initialMapLcg);
void RuntimeCoarseMapOracleBeginGenerationAttempt(unsigned int initialMapLcg);
void RuntimeCoarseMapOracleBeginAttempt();
void RuntimeCoarseMapOracleRecordDraw();
void RuntimeCoarseMapOracleCaptureSeededAttempt(const TMapMaker* mapMaker, unsigned int mapLcg);
void RuntimeCoarseMapOracleFinishAttempt(const TMapMaker* mapMaker, int errorCheckFailed,
                                         int hasContinuousOceanColumn, int frontierMaskComplete,
                                         int accepted, unsigned int mapLcg);
void RuntimeCoarseMapOracleCaptureExpansion(const TMapMaker* mapMaker, unsigned int mapLcg);
// Serializes the completed coarse trace once; caller does not own the value.
const JSON_Value* RuntimeCoarseMapOracleValue();

void RuntimeTerrainMapOracleReset(unsigned int initialMapLcg, int topologyByte, int desertQuota,
                                  int mountainQuota, int hillsQuota, int forestQuota,
                                  int swampQuota, int riverCount, int regionRows,
                                  int regionColumns);
void RuntimeTerrainMapOracleBeginAttempt(const TMapMaker* mapMaker, unsigned int mapLcg);
void RuntimeTerrainMapOracleCaptureStage(const char* stageName, const TMapMaker* mapMaker,
                                         unsigned int mapLcg);
void RuntimeTerrainMapOracleRecordRotationColumn(int column);
void RuntimeTerrainMapOracleCaptureKeywordStage(const TMapMaker* mapMaker, unsigned int mapLcg);
void RuntimeTerrainMapOracleResetSeedCandidates();
void RuntimeTerrainMapOracleRecordSeedCandidate(int terrainClass, int tileIndex);
void RuntimeTerrainMapOracleFinishAttempt(int accepted, unsigned int mapLcg);
// Serializes the completed terrain trace once; caller does not own the value.
const JSON_Value* RuntimeTerrainMapOracleValue();
int RuntimeTerrainMapOracleTopologyByte();

#endif
