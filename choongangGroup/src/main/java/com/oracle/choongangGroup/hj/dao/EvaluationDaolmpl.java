package com.oracle.choongangGroup.hj.dao;

import java.util.ArrayList;
import java.util.List;

import org.apache.ibatis.session.SqlSession;
import org.hibernate.validator.constraints.Length;
import org.springframework.stereotype.Repository;

import com.oracle.choongangGroup.hj.model.EvaluationVo;
import com.oracle.choongangGroup.hj.model.MemberVo;

import lombok.RequiredArgsConstructor;

@Repository
@RequiredArgsConstructor

public class EvaluationDaolmpl implements EvaluationDao {
	
	private final SqlSession session;

	@Override
	public List<EvaluationVo> evaluationList(String userid) {
		System.out.println("evaluationList evaluationList start. . . ");
		
		List<EvaluationVo> evaluation = new ArrayList<EvaluationVo>(); 
		
		try {
			System.out.println("userid2"+ userid);
			evaluation = session.selectList("hjevaluationSelOne",  userid); 
			System.out.println("EvaluationDaolmpl evaluationList -->" +evaluation.toString()) ;
			
			
		} catch (Exception e) {
			System.out.println("EvaluationDaolmpl evaluationList Exception-> "+e.getMessage());
		}
		
		
		return evaluation;
	}

	@Override
	public List<EvaluationVo> findev(String userid) {
		System.out.println("evaluationList findev start. . . ");
		List<EvaluationVo> evList =  null;
		try {
			
			evList=session.selectList("hjevSelList", userid);
			System.out.println(" findev userid----->"+userid);
			System.out.println("EvaluationDaolmpl evList -->" +evList.toString() ) ;
			
		} catch (Exception e) {
			System.out.println("EvaluationDaolmpl evaluationList Exception-> "+e.getMessage());
		}
		
		
		
		return evList;
	}

	@Override
	public List<EvaluationVo> findcg(String userid) {
		System.out.println("evaluationList findcg start. . . ");
		List<EvaluationVo> cgList = null;

		try {
			cgList=session.selectList("hjcgSelList");
			
			System.out.println("EvaluationDaolmpl findcg -->" +cgList.toString()) ;
			System.out.println(" findcg userid----->"+userid);
			
		} catch (Exception e) {
			System.out.println("EvaluationDaolmpl findcg Exception-> "+e.getMessage());

		}
		
		return cgList;
	}
	
	
	@Override
	public List<EvaluationVo> findcg2(String userid) {
		System.out.println("evaluationList***** findcg2 start. . . ");
		List<EvaluationVo> cgList2 = null;
		
		
		try {
			cgList2=session.selectList("hjcg2SelList");
			
			System.out.println("evaluationList findcg2 ****-->" +cgList2.toString()) ;
			
			
			
		} catch (Exception e) {
			System.out.println("EvaluationDaolmpl findcg Exception-> "+e.getMessage());

		}
		
		
		return cgList2;
	}
	
	
	


	  //강의평가 insert 
	@Override
	public int insertscore(EvaluationVo evaluationVo) {
	int result =0;
		
		try {
			result=session.insert("insertScore", evaluationVo );
			
			
		} catch (Exception e) {
			System.out.println("EvaluationDaolmpl insertscore Exception-> "+e.getMessage());

			
		}
		return result;
	}

	@Override
	public int updateEvaluation(EvaluationVo evaluation) {
		System.out.println("EvaluationDaolmpl updateEvaluation2222 start. . . ");
		int updateCount = 0;
		
		
		try {
			System.out.println("확인용 evaluation------------------>"+evaluation.toString());
			updateCount=session.update("hjEvaluationUpdate" ,evaluation);
			
			
			
		} catch (Exception e) {
			System.out.println("EvaluationDaolmpl 2222updateEvaluation Exception-> "+e.getMessage());
		}
		
		return updateCount;
	}


	@Override
	public int updateEv(EvaluationVo evaluationVo) {
		System.out.println("EvaluationDaolmpl updateEv start. . . ");
    int updateCount = 0;
		
		try {
			
			System.out.println("최종 : " + evaluationVo);
			System.out.println("최종형태 : " + evaluationVo.getBig_category());
			
			
			
			updateCount=session.update("hjupdateEv", evaluationVo );
			
			
			
		} catch (Exception e) {
			System.out.println("EvaluationDaolmpl updateEv Exception-> "+e.getMessage());

		}

		System.out.println(updateCount);
		
		return updateCount;
	}

	@Override
	public MemberVo infoList(String userid) {
		MemberVo memberinfo = new MemberVo();
		
		try {
			memberinfo = session.selectOne("hjEvMemberinfoSelOne", userid);
			
			
			
		} catch (Exception e) {
			System.out.println("EvaluationDaolmpl infoList Exception-> "+e.getMessage());
		}
		
		
		
		
		return memberinfo;
	}







}
