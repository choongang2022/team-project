package com.oracle.choongangGroup.sh.service;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.sh.domain.ApplicationLec;
import com.oracle.choongangGroup.sh.domain.ApplyTime;
import com.oracle.choongangGroup.sh.domain.Attendance;
import com.oracle.choongangGroup.sh.domain.Lecture;
import com.oracle.choongangGroup.sh.domain.Report;
import com.oracle.choongangGroup.sh.repository.ApplicationLecRepository;
import com.oracle.choongangGroup.sh.repository.ApplyRepository;
import com.oracle.choongangGroup.sh.repository.ApplyTimeRepository;
import com.oracle.choongangGroup.sh.repository.LectureRepository;
import com.oracle.choongangGroup.sh.repository.LikeRepository;

import lombok.RequiredArgsConstructor;

@Service
@Transactional
@RequiredArgsConstructor
public class ApplyServiceImpl implements ApplyService {
	
	private final LikeRepository lr;
	private final ApplyRepository ar;
	private final ApplyTimeRepository atr;
	private final LectureRepository lecr;
	private final ApplicationLecRepository aplr;
	private final ReportRepostiory rr;
	
	
	
	//장바구니, 수강 신청
	@Override
	public int apply(Long lecId, String userid, Long gubun) {
		int result = 0;
		Member member = ar.memberFindOne(userid);
		Lecture lecture = ar.lectureFindOne(lecId);
		ApplicationLec applyLec = ApplicationLec.apply(member, lecture, gubun);
		if(gubun == 1L) {
			result = lr.apply(applyLec); //장바구니 신청
		}else { 
			result = ar.apply(applyLec); //실제 수강신청
		}
		
		
		
		return result;
	}
	//장바구니, 수강신청 기간등록
	@Override
	public int register(ApplyTime applyTime) {
		String year = applyTime.getYear();
		String semester = applyTime.getSemester();
		String select = applyTime.getSelect();
		//0을 return하면 중복 메세지 alert
		int result = 0;
		int count = atr.countByYearAndSemesterAndSelect(year, semester, select);
		
			
		//중복시 update
		//update 기준은 select시 PK의 존재유무
		if(count >0) {
			//count==0 일때 하면 nullPointException 발생
			ApplyTime time = atr.findByYearAndSemesterAndSelect(year, semester, select);
			applyTime.setId(time.getId());
			atr.save(applyTime);
			result = 1;
		//중복없을시 insert
		}else {
			atr.save(applyTime);
		}
		return result;
		
	}

	@Override
	public ApplyTime findTime(String year, String semester, String select) {	
		ApplyTime applytime = new ApplyTime();
		applytime = atr.findByYearAndSemesterAndSelect(year, semester, select);
		
		return applytime;
	}
	
	//전체 과목리스트 페이징 처리
	@Override
	public Page<Lecture> lectureList(String year, String semester, Pageable pageable) {		
		return lecr.findAllByYearAndSemester(year, semester, pageable);
	}
	
	//장바구니 리스트 페이징
	@Override
	public Page<ApplicationLec> likeListPage(String userid, String year, String semester, Pageable pageable) {
		Long gubun = 1L; //장바구니 구분		
		return aplr.findAllByMember_UseridAndLecture_YearAndLecture_SemesterAndGubun(userid, year, semester, gubun, pageable);
	}

	//과목명으로 검색한 리스트 페이징
	@Override
	public Page<Lecture> findByName(String year, String semester, String lecName, Pageable pageable2) {
		return lecr.findByYearAndSemesterAndNameContaining(year,semester,lecName,pageable2);
	}

	//장바구니 리스트 조회
	@Override
	public List<ApplicationLec> likeList(String userid, String year, String semester) {
		Long gubun = 1L; //장바구니 구분
		return aplr.findAllByMember_UseridAndLecture_YearAndLecture_SemesterAndGubun(userid, year, semester, gubun);
	}
	//수강신청 리스트 조회
	@Override
	public List<ApplicationLec> applyList(String userid, String year, String semester) {
		Long gubun = 2L; //수강신청 구분
		return aplr.findAllByMember_UseridAndLecture_YearAndLecture_SemesterAndGubun(userid, year, semester, gubun);
	}
	
	//수강한 년도 리스트
	@Override
	public List<ApplicationLec> yearList(String userid) {	
		//aplr.findDistinctLecture_YearByMember_Userid(userid)
			
		return aplr.findByMember_Userid(userid);
		
	}
	@Override
	public ApplicationLec findByIdName(String userid, Long lecId) {
		
		return aplr.findByMember_UseridAndLecture_Id(userid,lecId);
	}
	@Override
	public void saveReport(Report report) {
		rr.save(report);
		
	}



	
	




	
















}
