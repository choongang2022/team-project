package com.oracle.choongangGroup.changhun.dept;

import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.oracle.choongangGroup.changhun.JPA.Dept;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@Transactional
public class DeptService {
	
	private final DeptRepository deptRepository;

	public List<Dept> searchDept(String search, String searchGubun) {
		
		List<Dept> searchDeptList = deptRepository.searchDept(search, searchGubun);
		
		return searchDeptList;
	}
}
