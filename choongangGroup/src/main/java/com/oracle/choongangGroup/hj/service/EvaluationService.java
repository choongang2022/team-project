package com.oracle.choongangGroup.hj.service;

import java.util.ArrayList;
import java.util.List;

import com.oracle.choongangGroup.hj.model.EvaluationVo;

public interface EvaluationService {

	List<EvaluationVo> list(String userid);

	List<EvaluationVo> findev(String userid);

	List<EvaluationVo> findcg(String userid);


	int insertscore(List<EvaluationVo> scoreList);

	List<EvaluationVo> findcg2(String userid);

	int updateEvaluation(EvaluationVo evaluation);

	int updateEv(ArrayList<EvaluationVo> rsList);









	
}
