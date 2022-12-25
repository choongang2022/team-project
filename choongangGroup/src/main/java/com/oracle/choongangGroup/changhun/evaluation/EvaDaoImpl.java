package com.oracle.choongangGroup.changhun.evaluation;

import java.util.List;

import org.apache.ibatis.session.SqlSession;
import org.springframework.stereotype.Repository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Repository
@Slf4j
@RequiredArgsConstructor
public class EvaDaoImpl implements EvaDao {

	private final SqlSession session;
	
	@Override
	public List<EvaVo> evaList(String pname) {
		
		List<EvaVo> evaList = session.selectList("evaVoFind",pname);
		
		log.info("evaList size --> {}",evaList.size());
		
		return evaList;
	}

	@Override
	public List<String> profList() {
		
		List<String> profList = session.selectList("profFind");
		
		System.out.println(profList.get(0));
		
		return profList;
	}

	@Override
	public EvaVo total(String pname) {
		
		EvaVo total = session.selectOne("totalFind", pname);
		
		return total;
	}

	@Override
	public List<EvaVo> reviewList(String pname) {
		
		List<EvaVo> reviewList = session.selectList("review",pname);
		
		return reviewList;
	}
	
	
}
