package com.oracle.choongangGroup.changhun.evaluation;

import java.util.List;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EvaService {
	
	private final EvaDao ed;

	public List<EvaVo> evaList(String pname) {
		
		List<EvaVo> evaList = ed.evaList(pname);

		return evaList;
	}

	public List<String> profList() {
		
		List<String> profList = ed.profList();
		
		return profList;
	}

	public EvaVo total(String pname) {
		
		EvaVo total = ed.total(pname);
		
		return total;
	}

	public List<EvaVo> reviewList(String pname) {
		
		List<EvaVo> reviewList = ed.reviewList(pname);
			
		return reviewList;
	}
	
}
