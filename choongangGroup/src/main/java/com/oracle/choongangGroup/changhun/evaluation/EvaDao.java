package com.oracle.choongangGroup.changhun.evaluation;

import java.util.List;

public interface EvaDao {

	List<EvaVo> evaList(String pname);

	List<String> profList();

	EvaVo total(String pname);

	List<EvaVo> reviewList(String pname);

}
