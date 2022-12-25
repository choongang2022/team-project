package com.oracle.choongangGroup.dongho.professor.report;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import com.oracle.choongangGroup.sh.domain.ApplicationLec;
import com.oracle.choongangGroup.sh.domain.Lecture;
import com.oracle.choongangGroup.sh.domain.Report;

public interface DhProfessorReportService {

	List<Lecture> findByProf(String profName);

	Page<ApplicationLec> findPageByLecture_IdAndGubun(Long id, Long gubun, Pageable pageable);

	int updateReportScore(Long id, String score, String grade);

	Report findByApplicationLec_Member_Userid(String userid);

	void save(Report report);

	List<ApplicationLec> findByLecture_IdAndGubun(Long id, Long gubun);

}
