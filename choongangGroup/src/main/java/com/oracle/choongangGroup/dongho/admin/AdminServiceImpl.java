package com.oracle.choongangGroup.dongho.admin;

import java.util.ArrayList;
import java.util.List;

import javax.transaction.Transactional;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class AdminServiceImpl implements AdminService {
	private final MemberListMapper memberListMapper;
	
	@Override
	public List<MemberPagingDto> memberPaging(int pageNum) {
		Criteria criteria = new Criteria(pageNum, 10);
		return memberListMapper.memberPaging(criteria);
	}

	@Override
	public int memberCount() {
		return memberListMapper.memberCount();
	}

	@Override
	public int deleteMember(ArrayList<String> deleteIdList) {
		int result = 0;
		result = memberListMapper.deleteMember(deleteIdList);
		return 0;
	}

}
