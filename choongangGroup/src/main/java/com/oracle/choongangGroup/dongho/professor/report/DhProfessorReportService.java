package com.oracle.choongangGroup.dongho.professor.report;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.oracle.choongangGroup.sh.domain.Lecture;

public interface DhProfessorReportService {

	List<Lecture> findByProf(String profName);

	ArrayList<Integer> updateReportScore(List<ReportUpdateDto> reportUpdateDtoList);

	String createZipAll(Long idToFind);

	String createZipSel(List<String> fileList);

	Map<String, Object> lecReportListPaging(Long id, int page);

}
