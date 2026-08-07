#ifndef IMPERIALISM_RUNTIME_COARSE_MAP_ORACLE_H
#define IMPERIALISM_RUNTIME_COARSE_MAP_ORACLE_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeCoarseMapOracle is test-only and must not be included in the production build
#endif

class CString;
class TMapMaker;

void RuntimeCoarseMapOracleReset(unsigned int initialMapLcg);
void RuntimeCoarseMapOracleBeginAttempt();
void RuntimeCoarseMapOracleRecordDraw();
void RuntimeCoarseMapOracleCaptureSeededAttempt(const TMapMaker* mapMaker, unsigned int mapLcg);
void RuntimeCoarseMapOracleFinishAttempt(const TMapMaker* mapMaker, int errorCheckFailed,
                                         int hasContinuousOceanColumn, int frontierMaskComplete,
                                         int accepted, unsigned int mapLcg);
void RuntimeCoarseMapOracleCaptureExpansion(const TMapMaker* mapMaker, unsigned int mapLcg);
const CString& RuntimeCoarseMapOracleJson();

#endif
