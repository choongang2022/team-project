package com.oracle.choongangGroup.dongho.professor.report;

import java.util.List;

import javax.transaction.Transactional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.stereotype.Service;

import com.oracle.choongangGroup.dongho.professor.repository.DhProfessorAppLecRepository;
import com.oracle.choongangGroup.dongho.professor.repository.DhProfessorLecRepository;
import com.oracle.choongangGroup.dongho.professor.repository.DhProfessorReportRepository;
import com.oracle.choongangGroup.sh.domain.ApplicationLec;
import com.oracle.choongangGroup.sh.domain.Lecture;
import com.oracle.choongangGroup.sh.domain.Report;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class DhProfessorReportServiceImpl implements DhProfessorReportService {
	private final DhProfessorLecRepository lr;
	private final DhProfessorReportRepository rr;
	private final DhProfessorAppLecRepository alr;
	
	@Override
	public List<Lecture> findByProf(String profName) {
		return lr.findByProf(profName);
	}

	@Override
	public Page<ApplicationLec> findPageByLecture_IdAndGubun(Long id, Long gubun, Pageable pageable) {
		return alr.findPageByLecture_IdAndGubun(id ,gubun, pageable);
	}

	@Override
	public int updateReportScore(Long id, String score, String grade) {
		int result = 0;
		try {
			log.info("service params : id : {}, score : {}, garde : {}", id, score, grade);
			result = rr.updateReportScore(id, score, grade);
		} catch (Exception e) {
			result = 0;
		}
		return result;
	}

	@Override
	public Report findByApplicationLec_Member_Userid(String userid) {
		return rr.findByApplicationLec_Member_Userid(userid);
	}

	@Override
	public void save(Report report) {
		rr.save(report);
	}

	@Override
	public List<ApplicationLec> findByLecture_IdAndGubun(Long id, Long gubun) {
		return alr.findByLecture_IdAndGubun(id, gubun);
	}

}
