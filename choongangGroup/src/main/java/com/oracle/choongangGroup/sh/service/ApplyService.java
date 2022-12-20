package com.oracle.choongangGroup.sh.service;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import com.oracle.choongangGroup.sh.domain.ApplicationLec;
import com.oracle.choongangGroup.sh.domain.ApplyTime;
import com.oracle.choongangGroup.sh.domain.Lecture;
import com.oracle.choongangGroup.sh.domain.Report;


public interface ApplyService {

	
	int apply(Long lecId, String userid, Long gubun);	//신청
	int register(ApplyTime applyTime);
	ApplyTime findTime(String year, String semester, String select);
	Page<Lecture> lectureList(String year, String semester, Pageable pageable); 
	Page<ApplicationLec> likeListPage(String userid, String year, String semester, Pageable pageable);
	Page<Lecture> findByName(String year, String semester, String lecName, Pageable pageable2);
	List<ApplicationLec> likeList(String userid, String year, String semester); //장바구니 목록
	List<ApplicationLec> applyList(String userid, String year, String semester);//수강신청 목록
	List<ApplicationLec> yearList(String userid);
	ApplicationLec findByIdName(String userid, Long lecId);
	void saveReport(Report report);
	




	

}
