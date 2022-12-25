package com.oracle.choongangGroup.hj.dao;

import java.util.List;

import com.oracle.choongangGroup.hj.model.EvaluationVo;

public interface EvaluationDao {

	List<EvaluationVo> evaluationList(String userid);

	List<EvaluationVo> findev(String userid);

	List<EvaluationVo> findcg(String userid);

	int insertscore(EvaluationVo evaluationVo);

	List<EvaluationVo> findcg2(String userid);

	int updateEvaluation(EvaluationVo evaluation);



	int updateEv(EvaluationVo evaluationVo);



	

}
